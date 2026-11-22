package console

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestReceiptActionsUseSameTicketAndLeaveSSHInput(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	answer := grant.Ticket{Claims: grant.Claims{Session: "only-this-receipt"}, Signature: []byte("fixture")}
	for _, screen := range []bool{true, false} {
		in, out := sshMenuInput(t, "c\nC\n\nv\nb\nfirst SSH command\n")
		copies := 0
		c := Console{in: in, out: out, fullScreen: screen, section: "控制端回执",
			copyToClipboard: func(_ context.Context, _ io.Writer, a grant.Ticket) (string, error) {
				copies++
				if a.Claims.Session != answer.Claims.Session || !bytes.Equal(a.Signature, answer.Signature) {
					t.Fatal("copied a different receipt")
				}
				return "已复制到系统剪贴板。", nil
			}}
		var keys receiptKeys
		state := active.State{Role: "control", Phase: "waiting", Exchange: "same.answer", Deadline: time.Now().Add(time.Hour)}
		if err := c.drawReceipt(t.Context(), state, answer, true, false); err != nil {
			t.Fatal(err)
		}
		c.receiptPrompt(state)
		for range 4 {
			open, err := c.receiptAction(t.Context(), &keys, state, answer)
			if err != nil || open {
				t.Fatal(open, err)
			}
		}
		if _, err := c.receiptAction(t.Context(), &keys, state, answer); !errors.Is(err, errBack) {
			t.Fatal(err)
		}
		if got, err := readLine(in); got != "first SSH command" || err != nil {
			t.Fatal("lost handoff input", got, err)
		}
		if copies != 4 || strings.Count(out.String(), "c 复制回执") != 5 || strings.Count(out.String(), ticketBegin) != 1 {
			t.Fatal("receipt actions or explicit text missing", copies)
		}
	}
}

func TestSingleUseReceiptStopsReadingBeforeSSH(t *testing.T) {
	t.Setenv("TERM", "dumb")
	in, out := sshMenuInput(t, "c\nfirst SSH command\n")
	copied := make(chan struct{})
	c := Console{in: in, out: out, interactive: true,
		copyToClipboard: func(context.Context, io.Writer, grant.Ticket) (string, error) {
			close(copied)
			return "已复制到系统剪贴板。", nil
		}}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	st := active.State{Role: "control", Phase: "gathering", Exchange: filepath.Join(t.TempDir(), "legacy.answer")}
	err := c.singleUseReceipt(ctx, st, false, func(ctx context.Context, publish func(grant.Ticket) error, ready func(string)) error {
		if err := publish(grant.Ticket{Claims: grant.Claims{Kind: "answer"}}); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-copied:
		}
		ready("udp")
		if got, err := readLine(in); err != nil || got != "first SSH command" {
			return fmt.Errorf("unexpected first SSH line %q: %v", got, err)
		}
		return nil
	})
	if err != nil || !strings.Contains(out.String(), "控制会话已连接") {
		t.Fatal(err, out.String())
	}
}

func TestActivityPreservesInputAndPlainTranscript(t *testing.T) {
	for _, screen := range []bool{true, false} {
		var out bytes.Buffer
		c := Console{out: &out, fullScreen: screen}
		c.setActivity("等待被控方批准")
		out.Reset()
		for range len(spinFrames) {
			c.advanceActivity()
		}
		if !screen {
			if out.Len() != 0 {
				t.Fatal("redirected output contains animation")
			}
			continue
		}
		for _, frame := range spinFrames {
			if !strings.Contains(out.String(), fmt.Sprintf("\x1b7\x1b[H%c\x1b8", frame)) {
				t.Fatal("animation did not restore the input cursor")
			}
		}
		c.setActivity("")
		out.Reset()
		c.advanceActivity()
		if out.Len() != 0 {
			t.Fatal("animation continued after handoff")
		}
	}
}
