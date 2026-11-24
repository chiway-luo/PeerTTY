//go:build linux || darwin

package localssh

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPrepareLoginCreatesAndCleansOnlyItsSessionDirectory(t *testing.T) {
	lookupErr := errors.New("fixture account lookup unavailable")
	preflightErr := errors.New("fixture SSH settings do not support scoped login")
	for _, tc := range []struct {
		name, username, home, want string
		lookup, verify             error
		root, probe                bool
	}{
		{name: "account lookup unavailable", lookup: lookupErr},
		{name: "root uses standard SSH", username: "root", root: true, want: "系统 SSH 登录"},
		{name: "unsupported account format", username: "unusable name", want: "系统 SSH 登录"},
		{name: "unsupported home format", username: "robot", home: "home%unexpanded", want: "主目录"},
		{name: "unavailable home directory", username: "robot", home: "missing", want: "missing"},
		{name: "preflight failure leaves no session material", username: "robot", verify: preflightErr, probe: true},
		{name: "preflight success returns a single scoped login", username: "robot", probe: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := root
			if tc.home != "" {
				home = filepath.Join(root, tc.home)
			}
			keep := filepath.Join(root, "existing")
			if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			calls := 0
			s, err := prepareLoginWith(ctx, func() (*user.User, error) {
				return &user.User{Username: tc.username, HomeDir: home}, tc.lookup
			}, func() int {
				if tc.root {
					return 0
				}
				return 1001
			}, func(probe context.Context, dir, account string, cred *syscall.Credential, port int) error {
				calls++
				if d, ok := probe.Deadline(); !ok || d.After(time.Now().Add(startupTimeout)) {
					t.Fatal("preflight did not inherit a bounded lifetime")
				}
				if filepath.Dir(dir) != home || !strings.HasPrefix(filepath.Base(dir), ".peertty-session-") || account != tc.username || cred != nil || port != 22 {
					t.Fatalf("preflight received unexpected session parameters: %q, %q, %v, %d", dir, account, cred, port)
				}
				info, err := os.Stat(filepath.Join(dir, "host.key"))
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
					t.Fatalf("missing or non-private session key: %v / %v", info, err)
				}
				return tc.verify
			})
			if (calls == 1) != tc.probe || calls > 1 {
				t.Fatalf("preflight calls=%d", calls)
			}
			if tc.probe && tc.verify == nil {
				if err != nil || s == nil || s.User != tc.username || len(s.HostKey) != ed25519.PublicKeySize {
					t.Fatalf("successful scoped login=%v / %v", s, err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			} else if s != nil || err == nil ||
				tc.lookup != nil && !errors.Is(err, tc.lookup) ||
				tc.verify != nil && !errors.Is(err, tc.verify) ||
				tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("login=%v error=%v, want %q/%v/%v", s, err, tc.want, tc.lookup, tc.verify)
			}
			got, err := os.ReadDir(root)
			if err != nil || len(got) != 1 || got[0].Name() != "existing" {
				t.Fatalf("unrelated files modified or session material left behind: %v / %v", got, err)
			}
		})
	}
}
