//go:build darwin || linux

package localssh

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestMissingOpenSSHAdviceSelectsLocalPackageManagerWithoutRunningIt(t *testing.T) {
	for _, tc := range []struct {
		name, platform, manager, pkg string
		server                       bool
		searched                     []string
	}{
		{"debian client", "linux", "/usr/bin/apt-get", "openssh-client", false, []string{"/usr/bin/apt-get"}},
		{"fedora client", "linux", "/usr/bin/dnf", "openssh-clients", false, []string{"/usr/bin/apt-get", "/usr/bin/dnf"}},
		{"yum server", "linux", "/usr/bin/yum", "openssh-server", true, []string{"/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/yum"}},
		{"no package manager", "linux", "", "", true, []string{"/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/yum"}},
		{"macOS", "darwin", "", "", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var searched []string
			var command []string
			got := missingOpenSSHWith(tc.server, tc.platform, func(exe string) (string, error) {
				searched = append(searched, exe)
				if tc.manager != "" && exe == tc.manager {
					return exe, nil
				}
				return "", exec.ErrNotFound
			}, func(message, label, exe string, args ...string) Check {
				command = append([]string{exe}, args...)
				return Check{Message: message, Action: label}
			})
			if !slices.Equal(searched, tc.searched) || got.Ready {
				t.Fatalf("lookups=%q; advice=%+v", searched, got)
			}
			if tc.manager == "" {
				if len(command) != 0 || got.Detail == "" || got.Action != "" {
					t.Fatalf("missing manual instructions or unexpected action: %+v / %q", got, command)
				}
			} else if !slices.Equal(command, []string{tc.manager, "install", tc.pkg}) || got.Action == "" ||
				strings.Contains(got.Message, "可能同时启动") != tc.server {
				t.Fatalf("wrong package or service-start warning: %+v / %q", got, command)
			}
		})
	}
}

func TestUnixConfigAdviceKeepsPlatformSpecificActionsSeparate(t *testing.T) {
	for _, tc := range []struct {
		name, platform, diag string
		uid                  int
		want                 []string
		prompt               bool
	}{
		{"linux missing keys", "linux", "no hostkeys available", 1000, []string{"/usr/bin/ssh-keygen", "-A"}, false},
		{"macOS missing keys", "darwin", "no hostkeys available", 501, nil, false},
		{"linux runtime directory", "linux", "Missing privilege separation directory: /run/sshd", 1000, []string{"/usr/bin/mkdir", "-m", "0755", "--", "/run/sshd"}, false},
		{"linux legacy directory alias", "linux", "Missing privilege separation directory: /var/run/sshd", 1000, []string{"/usr/bin/mkdir", "-m", "0755", "--", "/run/sshd"}, false},
		{"macOS does not offer linux directory fix", "darwin", "Missing privilege separation directory: /run/sshd", 501, nil, false},
		{"ordinary user may see authentication prompt", "linux", "sudo: a password is required", 1000, nil, true},
		{"root does not need a prompt", "linux", "sudo: a password is required", 0, nil, false},
		{"explicit refusal stays informational", "linux", "sudo: user is not allowed to execute sshd", 1000, nil, false},
		{"unrelated diagnostic stays informational", "linux", "invalid configuration", 1000, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var command []string
			got := unixConfigProblemFor(tc.diag, tc.platform, tc.uid, func(message, label, exe string, args ...string) Check {
				command = append([]string{exe}, args...)
				return Check{Message: message, Action: label}
			})
			if !slices.Equal(command, tc.want) || (got.Apply != nil) != tc.prompt || got.Ready || got.Message == "" ||
				(got.Action != "") != (len(tc.want) != 0 || tc.prompt) {
				t.Fatalf("wrong advice: command=%q, check=%+v", command, got)
			}
		})
	}
}
