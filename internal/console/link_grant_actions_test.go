package console

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
)

func TestEndGrantAllowsRevokingSelectedGrantDuringReconnect(t *testing.T) {
	cause := errors.New("fixture: worker still cleaning up")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"released", nil},
		{"cleanup is pending", cause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			key := filepath.Join(t.TempDir(), "fixture.key")
			info := active.State{ID: "chosen-grant", Role: "control", Phase: "disconnected"}
			var out bytes.Buffer
			statusCalls, revokeCalls := 0, 0
			err := endGrantWith(ctx, key, &out, func(c context.Context, path string) (active.State, error) {
				statusCalls++
				if c != ctx || path != key {
					t.Fatalf("status read the wrong identity: %q", path)
				}
				return info, nil
			}, func(c context.Context, path, id string) error {
				revokeCalls++
				if c != ctx || path != key || id != info.ID {
					t.Fatalf("revoke was not scoped to the selected authorization: %q / %q", path, id)
				}
				return tc.err
			})
			if !errors.Is(err, tc.err) || statusCalls != 1 || revokeCalls != 1 {
				t.Fatalf("unexpected status or revoke result: %v / %d / %d", err, statusCalls, revokeCalls)
			}
			want := ""
			if tc.err == nil {
				want = "本次授权已撤销。\n"
			}
			if out.String() != want {
				t.Fatalf("reported wrong result before cleanup: %q", out.String())
			}
		})
	}
}

func TestDisplayStatusShowsReconnectWithoutReportingEnded(t *testing.T) {
	key := filepath.Join(t.TempDir(), "fixture.key")
	var out bytes.Buffer
	err := displayStatusWith(t.Context(), key, &out, func(_ context.Context, path string) (active.State, error) {
		if path != key {
			t.Fatalf("checked wrong identity: %q", path)
		}
		return active.State{ID: "fixture-grant", Role: "control", Phase: "disconnected", Device: "fixture-device",
			Terminals: 2, Deadline: time.Now().Add(time.Minute), Note: "fixture network change"}, nil
	})
	log := out.String()
	if err != nil || strings.Contains(log, active.ErrInactive.Error()) {
		t.Fatalf("live grant appeared ended: %v / %q", err, log)
	}
	for _, want := range []string{"控制端 · 正在重连 · 2 个终端", "fixture-device", "fixture network change"} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in status: %q", want, log)
		}
	}
}

func TestIdentityPathReportsMissingDefaultHome(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Setenv("APPDATA", "")
	case "darwin":
		t.Setenv("HOME", "")
	default:
		t.Setenv("HOME", "")
		t.Setenv("XDG_CONFIG_HOME", "")
	}
	if _, err := os.UserConfigDir(); err == nil {
		t.Skip("platform supplies another config directory")
	}
	if path, err := IdentityPath("", ""); path != "" || err == nil {
		t.Fatalf("missing config home silently resolved to %q / %v", path, err)
	}
}
