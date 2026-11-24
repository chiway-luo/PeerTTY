package console

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestReceiptKeyboardPreservesPartialInputAcrossPollsAndErrors(t *testing.T) {
	in, _ := sshMenuInput(t, "  v  \nfirst SSH command\n")
	var keys receiptKeys
	probes := 0
	if value, ok, err := keys.readAvailable(in, func() (bool, error) {
		probes++
		return probes <= 3, nil
	}); value != "" || ok || err != nil || string(keys.partial) != "  v" {
		t.Fatalf("partial command not preserved: %q, %v, %v, partial %q", value, ok, err, keys.partial)
	}
	cause := errors.New("fixture key availability failed")
	if _, ok, err := keys.readAvailable(in, func() (bool, error) { return true, cause }); ok || !errors.Is(err, cause) || string(keys.partial) != "  v" {
		t.Fatalf("probe failure consumed input: %v / %v, partial %q", ok, err, keys.partial)
	}
	if value, ok, err := keys.readAvailable(in, func() (bool, error) { return true, nil }); value != "v" || !ok || err != nil || len(keys.partial) != 0 {
		t.Fatalf("resumed command = %q, %v, %v", value, ok, err)
	}
	if value, err := readLine(in); value != "first SSH command" || err != nil {
		t.Fatalf("keyboard consumed SSH input: %q / %v", value, err)
	}
	if _, ok, err := keys.readAvailable(in, func() (bool, error) { return true, nil }); ok || !errors.Is(err, io.EOF) {
		t.Fatalf("EOF not surfaced: %v / %v", ok, err)
	}
}

func TestReceiptKeyboardCapsReadWorkAndRejectsOversizedCommand(t *testing.T) {
	in, _ := sshMenuInput(t, strings.Repeat("x", 300)+"\nb\n")
	var keys receiptKeys
	probes := 0
	ready := func() (bool, error) { probes++; return true, nil }
	if got, ok, err := keys.readAvailable(in, ready); got != "" || ok || err != nil || probes != 256 || len(keys.partial) != 17 {
		t.Fatalf("overlong input monopolized poll: %q / %v / %v / %d polls", got, ok, err, probes)
	}
	if got, ok, err := keys.readAvailable(in, ready); got != "?" || !ok || err != nil || len(keys.partial) != 0 {
		t.Fatalf("oversized command not discarded: %q / %v / %v", got, ok, err)
	}
	if got, ok, err := keys.readAvailable(in, ready); got != "b" || !ok || err != nil {
		t.Fatalf("could not read next valid command: %q / %v / %v", got, ok, err)
	}
}

type receiptTextWriter struct {
	bytes.Buffer
	err error
}

func (w *receiptTextWriter) Write(p []byte) (int, error) {
	if bytes.HasPrefix(p, []byte("-----BEGIN")) {
		return 0, w.err
	}
	return w.Buffer.Write(p)
}

func TestReceiptActionEnterOnlyHandsOffReadySessionAndReturnsDisplayFailure(t *testing.T) {
	in, _ := sshMenuInput(t, "\nfirst SSH input\n")
	var readyKeys receiptKeys
	c := &Console{in: in, out: io.Discard}
	state := active.State{ID: "fixture", Phase: "ready", Deadline: time.Now().Add(time.Minute)}
	if open, err := c.receiptAction(t.Context(), &readyKeys, state, grant.Ticket{}); !open || err != nil {
		t.Fatalf("ready Enter did not hand off SSH: %v / %v", open, err)
	}
	if got, err := readLine(in); got != "first SSH input" || err != nil {
		t.Fatalf("handoff lost native input: %q / %v", got, err)
	}
	in, _ = sshMenuInput(t, "v\n")
	displayErr := errors.New("fixture could not write credential to terminal")
	out := &receiptTextWriter{err: displayErr}
	var waitingKeys receiptKeys
	c = &Console{in: in, out: out}
	state.Phase = "waiting"
	if open, err := c.receiptAction(t.Context(), &waitingKeys, state, grant.Ticket{}); open || !errors.Is(err, displayErr) {
		t.Fatalf("display failure not surfaced before handoff: %v / %v", open, err)
	}
}
