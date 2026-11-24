//go:build darwin || linux

package console

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"peertty/internal/active"
)

func TestLinkRecoveryWaitsForSameGrantAndNeverRelaunchesSSH(t *testing.T) {
	isolatedSSHClient(t, "exit 0")
	for _, replacement := range []bool{false, true} {
		name := "resume same grant"
		if replacement {
			name = "reject replacement grant"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			key := filepath.Join(dir, "device.key")
			in, err := os.Create(filepath.Join(dir, "input"))
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			diag, err := os.Create(filepath.Join(dir, "diag"))
			if err != nil {
				t.Fatal(err)
			}
			defer diag.Close()
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				initial := active.State{ID: "approved-session", Role: "control", Phase: "disconnected", Deadline: time.Now().Add(time.Minute)}
				recovered := initial
				recovered.Phase = "ready"
				recovered.Alias = "fixture-approved-device"
				recovered.User = "operator"
				if replacement {
					recovered.ID = "unselected"
				}
				calls, launches := 0, 0
				wantExit := errors.New("fixture SSH exit")
				err := linkSSHWithStatus(ctx, key, initial, in, io.Discard, diag, RemoteCommand{}, func(cmd *exec.Cmd) error {
					launches++
					if cmd.Stdin != in || cmd.Stderr != diag || !slices.Contains(cmd.Args, recovered.Alias) ||
						!slices.Contains(cmd.Env, "PEERTTY_LINK_ID="+initial.ID) ||
						!slices.Contains(cmd.Env, "PEERTTY_LINK_KEY="+key) {
						t.Error("SSH lost selected grant or stream configuration")
					}
					synctest.Wait()
					time.Sleep(3 * time.Second)
					synctest.Wait()
					return wantExit
				}, func(context.Context) (active.State, error) {
					calls++
					switch calls {
					case 1:
						return recovered, nil
					case 2:
						return initial, nil
					case 3:
						return recovered, nil
					default:
						return active.State{}, active.ErrInactive
					}
				})
				if replacement {
					if err == nil || !strings.Contains(err.Error(), "授权已结束") || launches != 0 || calls != 1 {
						t.Fatalf("replacement grant connected: %v calls=%d launches=%d", err, calls, launches)
					}
				} else if !errors.Is(err, wantExit) || launches != 1 || calls != 4 {
					t.Fatalf("recovery restarted SSH or lost exit error: %v calls=%d launches=%d", err, calls, launches)
				}
			})
			b, err := os.ReadFile(diag.Name())
			if err != nil {
				t.Fatal(err)
			}
			log := string(b)
			if !strings.Contains(log, reconnectNotice) || !replacement && (strings.Count(log, "直连已恢复") != 2 || !strings.Contains(log, reconnectRevokeHint) || !strings.Contains(log, "授权已结束")) {
				t.Fatalf("recovery diagnostics incomplete: %q", log)
			}
		})
	}
}
