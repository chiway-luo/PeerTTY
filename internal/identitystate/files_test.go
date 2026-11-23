package identitystate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIdentityLayoutAndLegacyImport(t *testing.T) {
	const name = "settings.json"
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	defaultDir := filepath.Join(config, "PeerTTY")
	if got := Path(filepath.Join(defaultDir, "device.key"), name); got != filepath.Join(defaultDir, name) {
		t.Fatalf("lost installed settings path: %s", got)
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")
	dst := Path(key, name)
	if dst == Path(filepath.Join(dir, "second.key"), name) || dst == filepath.Join(dir, name) {
		t.Fatal("custom identities share their settings")
	}
	legacy := filepath.Join(dir, name)
	write := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	importFile := func() {
		t.Helper()
		if err := ImportLegacy(key, name, 64, func(data []byte) bool { return string(data) == "recognized" }); err != nil {
			t.Fatal(err)
		}
	}
	write(legacy, "unrelated")
	importFile()
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("imported an unrelated file: %v", err)
	}
	write(legacy, "recognized")
	importFile()
	if got, err := Read(dst, 64); err != nil || string(got) != "recognized" {
		t.Fatalf("missing migrated data: %q %v", got, err)
	}
	write(dst, "newer")
	importFile()
	for path, want := range map[string]string{dst: "newer", legacy: "recognized"} {
		if got, err := Read(path, 64); err != nil || string(got) != want {
			t.Fatalf("import overwrote %s: %q %v", path, got, err)
		}
	}
}

func TestReadRejectsRedirectedStateDirectory(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "settings.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	path := Path(filepath.Join(dir, "custom.key"), "settings.json")
	if err := os.Symlink(other, filepath.Dir(path)); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := Read(path, 64); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("redirected state directory must be reported as unavailable: %v", err)
	}
}

func TestSharedWritableStateIsUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions")
	}
	path := Path(filepath.Join(t.TempDir(), "custom.key"), "known_peers.json")
	if err := EnsureDir(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 64); err == nil {
		t.Fatal("trusted state in a group-writable directory")
	}
	if err := Update(path, 64, func([]byte) ([]byte, error) { return []byte("changed"), nil }); err == nil {
		t.Fatal("updated state in a group-writable directory")
	}
}
