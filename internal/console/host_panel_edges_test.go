package console

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/localssh"
)

func TestHostPanelStopsOnCancellationBeforeReceivingInput(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := &Console{out: io.Discard, pending: make(chan line)}
	st := active.State{ID: "fixture", Phase: "gathering"}
	if err := c.hostPanel(ctx, st, nil, nil, hostPanelServices{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation reported as %v", err)
	}
}

func TestInteractiveHostStartsWithoutLinearBanner(t *testing.T) {
	var out bytes.Buffer
	c := &Console{out: &out, interactive: true}
	cause := errors.New("fixture SSH readiness unavailable")
	err := c.hostWith(t.Context(), hostStartServices{
		status: func(context.Context, string) (active.State, error) { return active.State{}, active.ErrInactive },
		ready:  func(context.Context) (localssh.Check, error) { return localssh.Check{}, cause },
	})
	if !errors.Is(err, cause) || out.Len() != 0 {
		t.Fatalf("unexpected readiness or linear output: %v %q", err, out.String())
	}
}

func TestHostPanelMissingOfferAndDisplayErrorsAreActionable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.offer")
	state := active.State{ID: "fixture", Phase: "waiting", Exchange: path, Note: "fixture system-SSH-only reason"}
	c := &Console{out: io.Discard}
	if err := c.hostPanel(t.Context(), state, nil, nil, hostPanelServices{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing offer became %v", err)
	}
	if err := (grant.Ticket{}).WriteNew(path); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("fixture terminal cannot write ticket")
	for _, interactive := range []bool{false, true} {
		out := &receiptTextWriter{err: cause}
		c := &Console{out: out, in: hostPanelInput(t, "v\n"), interactive: interactive}
		if err := c.hostPanel(t.Context(), state, nil, nil, hostPanelServices{}); !errors.Is(err, cause) {
			t.Fatalf("interactive=%t: lost output failure: %v", interactive, err)
		}
		if !strings.Contains(out.String(), state.Note) {
			t.Fatalf("interactive=%t: lost offer policy reason: %q", interactive, out.String())
		}
	}
}

func TestHostPanelDistinguishesRetryableInputFromReaderFailure(t *testing.T) {
	for _, inputErr := range []error{inputIssue("fixture input too long"), errors.New("fixture input lost")} {
		var out bytes.Buffer
		initial := make(chan line, 1)
		initial <- line{err: inputErr}
		c := &Console{out: &out, in: hostPanelInput(t, "ordinary text\n/back\n"), pending: initial, fullScreen: true}
		state := active.State{ID: "fixture", Phase: "ready", Deadline: time.Now().Add(time.Minute)}
		err := c.hostPanel(t.Context(), state, nil, nil, hostPanelServices{})
		if _, retryable := inputErr.(inputIssue); retryable {
			if !errors.Is(err, errBack) || !strings.Contains(out.String(), inputErr.Error()) || strings.Contains(out.String(), "授权继续有效。") {
				t.Fatalf("retryable input quit or lost its guidance: %v / %q", err, out.String())
			}
		} else if !errors.Is(err, inputErr) || strings.Contains(out.String(), inputErr.Error()) {
			t.Fatalf("fatal read failure was treated as a typo: %v / %q", err, out.String())
		}
	}
}

func TestHostPanelNonGatheringAnimationDoesNotPollStatus(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		spin := make(chan time.Time)
		pending := make(chan line)
		c := &Console{out: io.Discard, pending: pending}
		st := active.State{ID: "fixture", Phase: "ready"}
		result := make(chan error, 1)
		go func() {
			result <- c.hostPanel(ctx, st, spin, nil, hostPanelServices{
				status: func(context.Context, string) (active.State, error) { t.Error("animation polled grant"); return st, nil },
			})
		}()
		spin <- time.Now()
		synctest.Wait()
		pending <- line{text: "b"}
		if err := <-result; !errors.Is(err, errBack) {
			t.Fatalf("animation changed panel result: %v", err)
		}
	})
}
