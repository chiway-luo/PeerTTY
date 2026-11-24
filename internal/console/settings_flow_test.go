package console

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/grant"
)

func TestSettingsFlowCommitsOnlyAfterValidInputAndSave(t *testing.T) {
	for _, tc := range []struct {
		name, input, expectedSTUN, expectedNotice string
		port                                      int
		wantErr, malformed                        bool
	}{
		{"replace defaults", "none\nabc\n0\n65536\n2222\n", "none", "请输入 1–65535", 2222, false, false},
		{"reset STUN only", "-\n\n", "", "连接设置已应用", 22, false, false},
		{"cancel STUN prompt", "q\n", "auto", "", 22, true, false},
		{"cancel port after STUN", "none\nQ\n", "auto", "", 22, true, false},
		{"invalid STUN stops before port", "turn:example.invalid\n", "auto", "", 22, true, false},
		{"failed write preserves memory and file", "none\n2222\n", "auto", "", 22, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := filepath.Join(t.TempDir(), "device.key")
			in, out := sshMenuInput(t, tc.input)
			c := Console{in: in, out: out, Settings: Settings{KeyPath: key, STUN: "auto", SSHPort: 22}}
			const raw = "not JSON"
			path := settingsPath(key)
			if tc.malformed {
				putSettingsFixture(t, path, raw)
			}
			err := c.settings(t.Context())
			if (err != nil) != tc.wantErr || c.STUN != tc.expectedSTUN || c.SSHPort != tc.port {
				t.Fatalf("settings got %q/%d, %v; output %q", c.STUN, c.SSHPort, err, out)
			}
			if tc.expectedNotice != "" && !strings.Contains(out.String(), tc.expectedNotice) {
				t.Fatalf("missing notice %q in %q", tc.expectedNotice, out)
			}
			if tc.wantErr {
				if strings.Contains(out.String(), "连接设置已应用") {
					t.Fatalf("announced an unapplied change: %q", out)
				}
				data, readErr := os.ReadFile(path)
				if tc.malformed {
					if readErr != nil || string(data) != raw {
						t.Fatalf("failed write altered saved file: %q, %v", data, readErr)
					}
				} else if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("canceled or invalid input created settings: %v", readErr)
				}
				return
			}
			reloaded := Settings{KeyPath: key, STUN: "auto", SSHPort: 22}
			applySavedSettings(&reloaded)
			if reloaded.STUN != c.STUN || reloaded.SSHPort != c.SSHPort {
				t.Fatalf("persisted settings differ: %+v", reloaded)
			}
		})
	}
}

func TestMenuRefusesInvalidPortOrLifetimeBeforeIdentitySetup(t *testing.T) {
	for _, tc := range []struct {
		port int
		ttl  time.Duration
	}{
		{0, time.Hour},
		{65536, time.Hour},
		{22, 0},
		{22, grant.MaxTTL + time.Second},
	} {
		dir := filepath.Join(t.TempDir(), "not-created")
		err := Run(t.Context(), Settings{StateDir: dir, STUN: "none", SSHPort: tc.port, TTL: tc.ttl}, nil, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "SSH 端口或授权时长无效") {
			t.Fatalf("accepted port/lifetime %d/%s: %v", tc.port, tc.ttl, err)
		}
		if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("invalid settings touched local state: %v", statErr)
		}
	}
}

func TestUserPathHandlesQuotedHomePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, source := range []string{`'~/config file'`, `"~\config file"`} {
		got, err := userPath(source)
		if err != nil || got != filepath.Join(home, "config file") {
			t.Fatalf("userPath(%q) = %q (%v)", source, got, err)
		}
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if _, err := userPath("~/ssh"); err == nil {
		t.Fatal("missing home directory was silently ignored")
	}
}
