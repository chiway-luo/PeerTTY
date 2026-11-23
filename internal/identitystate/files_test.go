package identitystate

import (
	"errors"
	"os"
	"path/filepath"
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
