package console

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestInteractiveMenuBackAndSuccessfulLinkReturnToHome(t *testing.T) {
	in, out := sshMenuInput(t, "/back\n/link\n/connect\n/clipboard\n/clipboard\n/quit\n")
	key := filepath.Join(t.TempDir(), "fixture.key")
	c := &Console{Settings: Settings{KeyPath: key}, in: in, out: out, interactive: true, autoCopy: true}
	s := active.State{ID: "fixture", Role: "control", Phase: "ready"}
	links, panels := 0, 0
	if err := c.menuWithGrantActions(t.Context(), menuGrantActions{
		status: func(context.Context, string) (active.State, error) { return s, nil },
		link: func(_ context.Context, selected active.State) error {
			links++
			if selected != s {
				t.Errorf("wrong link authorization: %+v", selected)
			}
			return nil
		},
		panel: func(_ context.Context, selected active.State, text, review bool) error {
			panels++
			if selected != s || text || review {
				t.Errorf("wrong connect panel: %+v %t %t", selected, text, review)
			}
			return errBack
		},
	}); err != nil || links != 1 || panels != 1 || c.NoClipboard || !c.autoCopy {
		t.Fatalf("menu state invalid: %v, links=%d panels=%d clipboard=%t/%t", err, links, panels, c.NoClipboard, c.autoCopy)
	}
	for _, notice := range []string{"凭证自动复制已关闭", "凭证自动复制已开启"} {
		if strings.Count(out.String(), notice) != 1 {
			t.Errorf("missing or repeated %q: %q", notice, out.String())
		}
	}
}

func TestMenuCancellationDoesNotReportOperationFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	in, out := sshMenuInput(t, "/connect\n")
	c := &Console{in: in, out: out}
	want := errors.New("operation finished after cancellation")
	err := c.menuWithGrantActions(ctx, menuGrantActions{
		status:  func(context.Context, string) (active.State, error) { return active.State{}, active.ErrInactive },
		control: func(context.Context, string) error { cancel(); return want },
	})
	if !errors.Is(err, context.Canceled) || strings.Contains(out.String(), want.Error()) {
		t.Fatalf("canceled operation displayed error: %v, %q", err, out.String())
	}
}

func TestMenuDoesNotCreateIdentityInNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary-file")
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	in, out := sshMenuInput(t, "/quit\n")
	err := Run(t.Context(), Settings{StateDir: path, STUN: "none", TTL: time.Minute, SSHPort: 2222}, in, out)
	got, readErr := os.ReadFile(path)
	if err == nil || readErr != nil || string(got) != "preserve" || out.Len() != 0 {
		t.Fatalf("unexpected startup %v / %v, file=%q output=%q", err, readErr, got, out.String())
	}
}

func TestReceiptReviewWithoutInputRemainsReadOnly(t *testing.T) {
	answer := grant.Ticket{Claims: grant.Claims{Kind: "answer"}}
	file := filepath.Join(t.TempDir(), "fixture.answer")
	if err := answer.WriteNew(file); err != nil {
		t.Fatal(err)
	}
	_, out := sshMenuInput(t, "")
	c := &Console{out: out}
	changed := errors.New("fixture worker exited")
	err := c.receiptPanel(t.Context(), active.State{ID: "fixture", Phase: "ready", Exchange: file},
		true, true, reconnectTicks(3), receiptPanelServices{
			status: func(context.Context, string) (active.State, error) { return active.State{}, changed },
			link: func(context.Context, active.State) error {
				t.Fatal("review opened terminal without a user action")
				return nil
			},
		})
	if !errors.Is(err, changed) || !strings.Contains(out.String(), ticketBegin) {
		t.Fatalf("read-only review lost receipt or status: %v, %q", err, out.String())
	}
}

func TestReceiptPanelSurfacesInitialOutputFailure(t *testing.T) {
	answer := grant.Ticket{Claims: grant.Claims{Kind: "answer"}}
	file := filepath.Join(t.TempDir(), "fixture.answer")
	if err := answer.WriteNew(file); err != nil {
		t.Fatal(err)
	}
	want := errors.New("fixture receipt output failed")
	c := &Console{out: &receiptTextWriter{err: want}}
	st := active.State{ID: "fixture", Phase: "waiting", Exchange: file}
	if err := c.receiptPanel(t.Context(), st, true, false, nil, receiptPanelServices{}); !errors.Is(err, want) {
		t.Fatalf("panel swallowed credential output error: %v", err)
	}
}

func TestReceiptLinkWhileWaitingAndInputEnd(t *testing.T) {
	in, _ := sshMenuInput(t, "/link\n")
	c := &Console{in: in, out: io.Discard}
	st := active.State{Phase: "waiting"}
	var keys receiptKeys
	if open, err := c.receiptAction(t.Context(), &keys, st, grant.Ticket{}); open || err != nil {
		t.Fatalf("waiting receipt attempted a terminal: %t / %v", open, err)
	}
	if open, err := c.receiptAction(t.Context(), &keys, st, grant.Ticket{}); open || (err != nil && !errors.Is(err, io.EOF)) {
		t.Fatalf("closed input attempted a terminal: %t / %v", open, err)
	}
}
