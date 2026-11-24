//go:build darwin || linux

package localssh

import (
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestLoginOwnerRecognizesOnlyScopedPathForOrdinaryAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Setenv("SUDO_UID", "")
		if account, cred, err := loginOwner(t.TempDir()); account != nil || cred != nil || err == nil {
			t.Fatalf("root without approved ordinary account: %v %v %v", account, cred, err)
		}
		return
	}
	current, err := user.Current()
	if err != nil || !filepath.IsAbs(current.HomeDir) || !accountName.MatchString(current.Username) {
		t.Skip("standard Unix user account is required")
	}
	// The owner check is path validation only. No directory is created in the actual home.
	scoped := filepath.Join(current.HomeDir, ".peertty-session-unit-fixture")
	account, cred, err := loginOwner(scoped)
	if err != nil || account == nil || account.Uid != current.Uid || cred != nil {
		t.Fatalf("owner check failed: %v", err)
	}
	for _, path := range []string{
		filepath.Join(current.HomeDir, "ordinary-directory"),
		filepath.Join(t.TempDir(), ".peertty-session-unrelated"),
		scoped + string(filepath.Separator),
	} {
		if account, cred, err := loginOwner(path); account != nil || cred != nil || err == nil || !strings.Contains(err.Error(), "不属于批准账号") {
			t.Fatalf("non-eligible directory passed owner check: %q %v", path, err)
		}
	}
}

func TestLoginSSHDCommandKeepsScopedOptionsWithoutExecuting(t *testing.T) {
	dir := t.TempDir()
	for _, credential := range []*syscall.Credential{nil, {Uid: 501, Gid: 20}} {
		cmd := loginSSHD(t.Context(), dir, credential, "-T")
		if cmd.Path != sshd || !slices.Contains(cmd.Args, "-T") ||
			!slices.Contains(cmd.Args, "DisableForwarding=yes") || !slices.Contains(cmd.Args, filepath.Join(dir, "host.key")) {
			t.Fatalf("unexpected command: %v", cmd.Args)
		}
		if credential == nil && cmd.SysProcAttr != nil || credential != nil && (cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential != credential) {
			t.Fatal("invocation lost expected execution identity")
		}
	}
}

func TestGuardChecksRejectMissingOrWritablePathsWithoutRunningCommands(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	writable := filepath.Join(dir, "writable")
	if err := os.WriteFile(writable, []byte("not an executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0666); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{missing, writable} {
		if adminOwned(path) {
			t.Fatalf("trusted unavailable or writable guard %q", path)
		}
	}
	cmd := guardCmd(missing, "1234")
	if len(cmd.Args) < 3 || cmd.Args[len(cmd.Args)-2] != GuardCommand || cmd.Args[len(cmd.Args)-1] != "1234" {
		t.Fatalf("guard command missing expected arguments: %v", cmd.Args)
	}
	if cmd.Path == "/usr/bin/sudo" && slices.Contains(cmd.Args, missing) {
		t.Fatal("proposed a privilege prompt for the missing portable guard")
	}
}
