//go:build darwin || linux

package console

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/localssh"
)

func TestLegacyControllerReturnsSSHResultAndCleansTemporaryHandoff(t *testing.T) {
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	invitation, err := grant.NewPairingOffer(host, "fixture-only", "robot", deadline)
	if err != nil {
		t.Fatal(err)
	}
	invite := filepath.Join(t.TempDir(), "invite.json")
	if err := fixtureCode.Seal(&invitation); err != nil {
		t.Fatal(err)
	}
	if err := invitation.WriteNew(invite); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		interactive   bool
	}{
		{"plain success", "printf 'fixture SSH\\n'; exit 0", false},
		{"return to menu", "exit 0", true},
		{"preserve error", "exit 37", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)
			isolatedSSHClient(t, tc.command)
			in, out := sshMenuInput(t, string(fixtureCode)+"\n\n\n")
			ui := Console{Settings: Settings{KeyPath: filepath.Join(dir, "device.key"), STUN: "none"},
				in: in, out: out, interactive: tc.interactive}
			err := ui.controlWith(t.Context(), invite, controllerServices{
				check:  func() localssh.Check { return localssh.Check{Ready: true} },
				status: func(context.Context, string) (active.State, error) { return active.State{}, active.ErrInactive },
				start: func(context.Context, active.Options) (active.State, error) {
					t.Fatal("legacy offer used reusable worker")
					return active.State{}, nil
				},
			})
			switch tc.name {
			case "plain success":
				if err != nil || !strings.Contains(out.String(), "fixture SSH") || !strings.Contains(out.String(), "控制会话已结束") {
					t.Fatalf("plain output=%q err=%v", out, err)
				}
			case "return to menu":
				if !errors.Is(err, errBack) {
					t.Fatalf("interactive return=%v", err)
				}
			case "preserve error":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 37 || !strings.Contains(err.Error(), "SSH 连接结束") {
					t.Fatalf("exit status lost: %v", err)
				}
			}
			scratch, err := filepath.Glob(filepath.Join(dir, "peertty-control-*"))
			if err != nil || len(scratch) != 0 {
				t.Fatalf("temporary handoff not cleaned: %v / %v", scratch, err)
			}
		})
	}
}
