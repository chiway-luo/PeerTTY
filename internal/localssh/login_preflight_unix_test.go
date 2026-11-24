//go:build linux || darwin

package localssh

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestScopedLoginPreflightRespectsExistingAccountAndPortPolicy(t *testing.T) {
	const basePolicy = "authorizedkeysfile .ssh/authorized_keys\nauthenticationmethods any\npubkeyauthentication yes\nmaxsessions 1\n"
	var fixtureFailure = errors.New("fixture ssh configuration error")
	for _, tc := range []struct {
		name, diag, want                         string
		port, calls                              int
		failAt                                   int
		blockBase, differentPort, blockTemporary bool
	}{
		{name: "default port", port: 22, calls: 2},
		{name: "matching policy at ephemeral port", port: 41000, calls: 3},
		{name: "unreadable sshd config", port: 22, calls: 1, failAt: 1, diag: "sshd_config: Permission denied", want: "无权读取系统 sshd_config"},
		{name: "base probe failed", port: 22, calls: 1, failAt: 1, diag: "missing host keys", want: "无法读取本机 SSH 账号策略"},
		{name: "account needs existing credentials", port: 22, calls: 1, blockBase: true, want: "已有的登录凭据"},
		{name: "policy changes by port", port: 41000, calls: 2, differentPort: true, want: "独立策略"},
		{name: "second probe unavailable", port: 41000, calls: 2, failAt: 2, want: "独立策略"},
		{name: "temporary mode probe failed", port: 41000, calls: 3, failAt: 3, want: "无法启用"},
		{name: "temporary policy not sufficiently scoped", port: 22, calls: 2, blockTemporary: true, want: "disableforwarding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cred := &syscall.Credential{Uid: 1001, Gid: 1002}
			calls := 0
			err := verifyLoginSSHDWith(t.Context(), dir, "fixture", cred, tc.port, func(cmd *exec.Cmd) ([]byte, error) {
				calls++
				port := tc.port
				if calls == 1 {
					port = 22
				}
				if cmd.Path != sshd || cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential != cred ||
					!slices.Contains(cmd.Args, "-T") ||
					!slices.Contains(cmd.Args, filepath.Join(dir, "host.key")) ||
					!slices.Contains(cmd.Args, fmt.Sprintf("user=fixture,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=%d", port)) {
					t.Fatalf("incorrect dry-run command or selected account: %q", cmd.Args)
				}
				scoped := slices.Contains(cmd.Args, "DisableForwarding=yes")
				if scoped != (calls > 1 && (tc.port == 22 || calls == 3)) {
					t.Fatalf("scoped options unexpectedly present or missing on probe %d", calls)
				}
				if calls == tc.failAt {
					if tc.diag != "" {
						if cmd.Stderr == nil {
							t.Fatal("missing stderr capture")
						}
						_, _ = io.WriteString(cmd.Stderr, tc.diag)
					}
					return nil, fixtureFailure
				}
				if !scoped {
					policy := basePolicy
					if tc.blockBase {
						policy = strings.Replace(policy, "authenticationmethods any", "authenticationmethods publickey,password", 1)
					}
					if tc.differentPort && calls == 2 {
						policy = strings.Replace(policy, "maxsessions 1", "maxsessions 2", 1)
					}
					return []byte(policy), nil
				}
				policy := fmt.Sprintf("pubkeyauthentication yes\nauthorizedkeysfile %q\ntrustedusercakeys none\ndisableforwarding yes\npasswordauthentication no\nmaxsessions 1\nauthenticationmethods publickey\nauthorizedkeyscommand none\nhostbasedauthentication no\nkbdinteractiveauthentication no\npermitrootlogin no\n", filepath.ToSlash(filepath.Join(dir, "authorized-%u")))
				if tc.blockTemporary {
					policy = strings.Replace(policy, "disableforwarding yes", "disableforwarding no", 1)
				}
				return []byte(policy), nil
			})
			if calls != tc.calls || (tc.want == "" && err != nil) || (tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want))) {
				t.Fatalf("probes=%d (want %d), result=%v (want %q)", calls, tc.calls, err, tc.want)
			}
		})
	}
}
