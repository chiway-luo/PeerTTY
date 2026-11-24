package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
)

func TestMenuUnavailableGrantCommandsDoNotStartASession(t *testing.T) {
	in, out := sshMenuInput(t, "/link\n/receipt\n/revoke\n/clipboard\n/clipboard\n/quit\n")
	dir := t.TempDir()
	if err := Run(t.Context(), Settings{StateDir: dir, STUN: "none", TTL: time.Hour, SSHPort: 2222}, in, out); err != nil {
		t.Fatal(err)
	}
	log := out.String()
	if got := strings.Count(log, active.ErrInactive.Error()); got < 3 {
		t.Fatalf("only %d commands reported inactive:\n%s", got, log)
	}
	for _, want := range []string{"凭证自动复制已关闭", "凭证自动复制已开启"} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q: %s", want, log)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "device.key.active")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inactive commands started a worker: %v", err)
	}
	opts := Settings{KeyPath: filepath.Join(dir, "device.key"), NoClipboard: true}
	applySavedSettings(&opts)
	if opts.NoClipboard {
		t.Fatal("final toggle did not persist")
	}
}

func TestMenuBootstrapReportsInvalidLocalConfigurationWithoutSideEffects(t *testing.T) {
	dir := t.TempDir()
	asFile := filepath.Join(dir, "ordinary-file")
	if err := os.WriteFile(asFile, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, stun, state, key, want string
		missing                      bool
	}{
		{"invalid STUN", "turn:example.invalid", dir, "", "STUN", false},
		{"state directory is a file", "none", asFile, "", "", false},
		{"missing profile parent is a file", "none", asFile + "/child", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out := sshMenuInput(t, "/quit\n")
			err := Run(t.Context(), Settings{StateDir: tc.state, KeyPath: tc.key, STUN: tc.stun, TTL: time.Hour, SSHPort: 2222}, in, out)
			if err == nil || out.Len() != 0 || tc.missing && !errors.Is(err, os.ErrNotExist) || tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected config response: %v / %q", err, out.String())
			}
		})
	}
	for _, path := range []string{filepath.Join(dir, "device.key"), filepath.Join(dir, "missing.key")} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected identity created: %v", err)
		}
	}
}

func TestCanceledMenuReturnsBeforeWaitingForInput(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, out := sshMenuInput(t, "")
	menu := Console{out: out}
	if err := menu.menu(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("menu returned %v", err)
	}
}

func TestMenuBackRefreshesTerminalHomeAfterHelp(t *testing.T) {
	in, out := sshMenuInput(t, "/help\n/back\n/quit\n")
	c := Console{in: in, out: out, interactive: true, Settings: Settings{KeyPath: filepath.Join(t.TempDir(), "device.key"), Version: "fixture-menu-version", SSHPort: 2222}}
	if err := c.menu(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), "fixture-menu-version"); got != 2 {
		t.Fatalf("expected home to render before help and after back, %d renders: %q", got, out.String())
	}
}

func TestMenuPropagatesNonEOFInputFailure(t *testing.T) {
	_, out := sshMenuInput(t, "")
	pending := make(chan line, 1)
	failure := errors.New("fixture terminal read failure")
	pending <- line{err: failure}
	c := Console{out: out, pending: pending, Settings: Settings{KeyPath: filepath.Join(t.TempDir(), "device.key")}}
	if err := c.menu(t.Context()); !errors.Is(err, failure) {
		t.Fatalf("input failure was swallowed: %v", err)
	}
	if c.pending != nil {
		t.Fatal("menu retained consumed input after failure")
	}
}
