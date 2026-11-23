//go:build darwin || linux

package localssh

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestUnixSSHDiagnosticsOfferTheExpectedAction(t *testing.T) {
	cases := []struct {
		output, message string
		action          bool
	}{
		{"sshd: no hostkeys available -- exiting.", "主机密钥", runtime.GOOS != "darwin"},
		{"account is not in the sudoers file", "管理员权限", false},
		{"user is not allowed to execute this command", "管理员权限", false},
		{"unknown sshd_config setting", "配置未通过", false},
	}
	for _, tc := range cases {
		check := unixConfigProblem(tc.output)
		if check.Ready || !strings.Contains(check.Message, tc.message) || (check.Apply != nil) != tc.action {
			t.Errorf("diagnostic %q: %s, action %q", tc.output, check.Message, check.Action)
		}
	}
	if runtime.GOOS == "linux" {
		check := unixConfigProblem("Missing privilege separation directory: /run/sshd")
		if check.Apply == nil || !strings.Contains(check.Action, "/run/sshd") {
			t.Fatal("missing runtime directory did not offer a matching repair")
		}
	}
	if os.Geteuid() != 0 {
		check := unixConfigProblem("sudo: a password is required")
		if check.Ready || check.Apply == nil || !strings.Contains(check.Action, "验证") {
			t.Fatal("missing local approval prompt")
		}
	}
}
