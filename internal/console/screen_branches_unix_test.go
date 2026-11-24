//go:build darwin || linux

package console

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"peertty/internal/active"
)

func TestScreenSetupBalancesAlternateBufferOnExit(t *testing.T) {
	for _, tc := range []struct {
		term               string
		interactive, enter bool
	}{
		{"xterm", true, true},
		{"dumb", true, false},
		{"xterm", false, false},
	} {
		t.Setenv("TERM", tc.term)
		out, err := os.CreateTemp(t.TempDir(), "screen")
		if err != nil {
			t.Fatal(err)
		}
		c := Console{out: out, interactive: tc.interactive}
		closeScreen := c.openScreen()
		if c.fullScreen != tc.enter {
			t.Errorf("TERM=%s interactive=%v: entered screen = %v", tc.term, tc.interactive, c.fullScreen)
		}
		closeScreen()
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out.Name())
		if err != nil {
			t.Fatal(err)
		}
		want := ""
		if tc.enter {
			want = enterScreen + leaveScreen
		}
		if c.fullScreen || string(b) != want {
			t.Fatalf("unbalanced screen: full=%v, transcript=%q, want=%q", c.fullScreen, b, want)
		}
	}
}

func TestStatusMenuRecoversInputWithoutTriggeringAnAction(t *testing.T) {
	in, out := sshMenuInput(t, pasteStart+"bad"+pasteEnd+"extra\n/revoke\nremaining\n")
	c := Console{in: in, out: out, interactive: true, Settings: Settings{KeyPath: filepath.Join(t.TempDir(), "fixture.key")}}
	choice, err := c.menuChoice(t.Context(), statusPage)
	if err != nil || choice != "/revoke" || c.pending != nil {
		t.Fatalf("status menu result=%q, %v, pending=%v", choice, err, c.pending)
	}
	if log := out.String(); strings.Count(log, incompletePaste.Error()) != 1 || strings.Count(log, active.ErrInactive.Error()) != 2 {
		t.Fatalf("input recovery did not redraw current status: %q", log)
	}
	if text, err := readLine(in); err != nil || text != "remaining" {
		t.Fatalf("menu consumed next entry: %q / %v", text, err)
	}
}

func TestHelpCancellationDoesNotConsumePendingTerminalRead(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out bytes.Buffer
	pending := make(chan line, 1)
	c := Console{out: &out, pending: pending, interactive: true}
	if text, err := c.menuChoice(ctx, helpPage); text != "" || !errors.Is(err, context.Canceled) || c.pending != pending {
		t.Fatalf("canceled help discarded pending input: %q, %v", text, err)
	}
	pending <- line{text: "next"}
	if text, err := c.menuChoice(t.Context(), resultPage); text != "next" || err != nil || c.pending != nil {
		t.Fatalf("next page lost input: %q, %v", text, err)
	}
}
