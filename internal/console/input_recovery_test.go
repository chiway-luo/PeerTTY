package console

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"peertty/internal/grant"
)

func TestMenuRecoversFromPasteErrorsWithoutConsumingNextEntry(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        error
	}{
		{"oversized plain line", strings.Repeat("x", grant.MaxTicketSize+1) + "\nnext\n", oversizePaste},
		{"interrupted framing", pasteStart + "one" + pasteEnd + "extra\nnext\n", incompletePaste},
		{"oversized armored line", ticketBegin + "\n" + strings.Repeat("x", grant.MaxTicketSize+1) + "\n" + ticketEnd + "\nnext\n", oversizePaste},
		{"oversized armored block", ticketBegin + "\n" + strings.Repeat(strings.Repeat("x", maxPaste/4)+"\n", 6) + ticketEnd + "\nnext\n", oversizePaste},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out := sshMenuInput(t, tc.input)
			c := &Console{in: in, out: out}
			got, err := c.ask(t.Context(), "input: ")
			if err != nil || got != "next" || strings.Count(out.String(), "input: ") != 2 ||
				!strings.Contains(out.String(), tc.want.Error()) {
				t.Fatalf("got %q, %v; transcript %q", got, err, out.String())
			}
			if _, err := c.ask(t.Context(), "again: "); !errors.Is(err, io.EOF) {
				t.Fatalf("expected exhausted input, got %v", err)
			}
		})
	}
}

func TestCancelledPromptHandsItsPendingInputToNextPrompt(t *testing.T) {
	_, out := sshMenuInput(t, "")
	pending := make(chan line, 1)
	c := &Console{out: out, pending: pending}
	ctx, stop := context.WithCancel(t.Context())
	stop()
	if got, err := c.ask(ctx, "cancelled: "); got != "" || !errors.Is(err, context.Canceled) || c.pending != pending {
		t.Fatalf("cancelled prompt consumed pending read: %q, %v", got, err)
	}
	pending <- line{text: "remaining input"}
	if got, err := c.ask(t.Context(), "active: "); got != "remaining input" || err != nil || c.pending != nil {
		t.Fatalf("replacement prompt = %q, %v", got, err)
	}
}
