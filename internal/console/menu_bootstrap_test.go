package console

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"peertty/internal/grant"
)

func TestMenuDefaultConfigDoesNotCreateIdentity(t *testing.T) {
	dir := t.TempDir()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("APPDATA", dir)
	case "darwin":
		t.Setenv("HOME", dir)
	default:
		t.Setenv("XDG_CONFIG_HOME", dir)
	}
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(config, "PeerTTY", "device.key")
	opts := Settings{STUN: "none", TTL: time.Hour, SSHPort: 2222}
	for range 2 {
		in, out := sshMenuInput(t, "/quit\n")
		if err := Run(t.Context(), opts, in, out); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("idle menu created a key: %v", err)
		}
	}
	if _, err := os.Stat(path + ".active"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("menu startup changed the active grant: %v", err)
	}
}

func TestMenuStartupReportsLegacyStoreAccessErrors(t *testing.T) {
	for _, name := range []string{"settings.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			key := filepath.Join(dir, "device.key")
			if _, err := grant.NewIdentity(key); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
				t.Fatal(err)
			}
			in, out := sshMenuInput(t, "/quit\n")
			err := Run(t.Context(), Settings{KeyPath: key, StateDir: dir, STUN: "none", SSHConfig: "'./fixture config'", TTL: time.Hour, SSHPort: 2222}, in, out)
			if err == nil || !strings.Contains(err.Error(), name) || out.Len() != 0 {
				t.Fatalf("startup entered menu despite unreadable legacy %s: %v, %q", name, err, out.String())
			}
			if _, err := os.Stat(key + ".peertty"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("startup created migrated state on failure: %v", err)
			}
		})
	}
}

func TestMenuMissingConfigHomeReturnsBeforeCreatingIdentity(t *testing.T) {
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
		t.Skip("runtime supplies another config home fallback")
	}
	in, out := sshMenuInput(t, "/quit\n")
	err := Run(t.Context(), Settings{STUN: "none", TTL: time.Minute, SSHPort: 2222}, in, out)
	if err == nil || out.Len() != 0 {
		t.Fatalf("missing home should fail without entering menu: %v, %q", err, out.String())
	}
}

func TestMenuReturnsToPromptAfterLocalHostAndDoctorErrors(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	if err := os.WriteFile(key+".active", []byte("unavailable"), 0600); err != nil {
		t.Fatal(err)
	}
	in, out := sshMenuInput(t, "/host\n/doctor\n/quit\n")
	c := Console{Settings: Settings{KeyPath: key, STUN: "invalid fixture value"}, in: in, out: out}
	if err := c.menu(t.Context()); err != nil {
		t.Fatal(err)
	}
	output := out.String()
	if strings.Count(output, "操作结束") != 2 || !strings.Contains(output, "STUN 地址") || !strings.Contains(output, "不能读取本机授权状态") {
		t.Fatalf("expected both local errors and a clean exit: %q", output)
	}
}

func TestMenuReportsSettingsWriteFailureAndKeepsCurrentClipboardPreference(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")
	if err := os.WriteFile(key+".peertty", []byte("not a settings directory"), 0600); err != nil {
		t.Fatal(err)
	}
	in, out := sshMenuInput(t, "/clipboard\n/quit\n")
	c := Console{in: in, out: out, Settings: Settings{KeyPath: key, NoClipboard: true}}
	if err := c.menu(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !c.NoClipboard || c.autoCopy || !strings.Contains(out.String(), "操作结束") ||
		strings.Contains(out.String(), "凭证自动复制已开启") {
		t.Fatalf("failed settings write changed clipboard preference: %q", out.String())
	}
}

func TestMenuStartupRejectsUnresolvableSSHConfigWithoutOpeningMenu(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", "")
	} else {
		t.Setenv("HOME", "")
	}
	_, homeErr := os.UserHomeDir()
	if homeErr == nil {
		t.Skip("runtime supplies another home directory fallback")
	}
	key := filepath.Join(t.TempDir(), "device.key")
	in, out := sshMenuInput(t, "/quit\n")
	err := Run(t.Context(), Settings{KeyPath: key, STUN: "none", SSHConfig: `"~/ssh config"`, TTL: time.Hour, SSHPort: 2222}, in, out)
	if err == nil || err.Error() != homeErr.Error() || out.Len() != 0 {
		t.Fatalf("expected SSH path resolution error before identity lookup or UI: %v, %q", err, out.String())
	}
}

func TestMenuDefaultIdentityKeepsDanglingSymlinkUntouched(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")
	target := filepath.Join(dir, "missing", "identity")
	if err := os.Symlink(target, key); err != nil {
		t.Skipf("cannot create fixture symlink: %v", err)
	}
	in, out := sshMenuInput(t, "/quit\n")
	err := Run(t.Context(), Settings{StateDir: dir, STUN: "none", SSHPort: 2222, TTL: time.Hour}, in, out)
	if err != nil || out.Len() == 0 {
		t.Fatalf("unused dangling identity blocked the menu: %v, %q", err, out.String())
	}
	if value, err := os.Readlink(key); err != nil || value != target {
		t.Fatalf("first-run creation replaced the existing identity symlink: %q, %v", value, err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first-run creation touched missing symlink target: %v", err)
	}
}

func TestUserPathPreservesUnbalancedQuotesAndExpandsBothHomeSeparators(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	for _, input := range []string{`"~/fixture config"`, `'~\fixture config'`} {
		if got, err := userPath(input); err != nil || got != filepath.Join(home, "fixture config") {
			t.Fatalf("unexpected home path for %q: %q, %v", input, got, err)
		}
	}
	for _, input := range []string{`"fixture'`, `'fixture"`} {
		want, err := filepath.Abs(input)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := userPath(input); err != nil || got != want {
			t.Fatalf("removed unbalanced quotes in %q: %q, %v", input, got, err)
		}
	}
}
