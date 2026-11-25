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
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
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

func TestStateUpdateRejectsInvalidWritesWithoutReplacingData(t *testing.T) {
	path := Path(filepath.Join(t.TempDir(), "device.key"), "settings.json")
	keep := []byte("original")
	if err := Update(path, 8, func([]byte) ([]byte, error) { return keep, nil }); err != nil {
		t.Fatal(err)
	}
	callbackErr := errors.New("edit canceled")
	for _, tc := range []struct {
		name    string
		value   []byte
		err     error
		wantErr bool
	}{
		{"no change", nil, nil, false},
		{"callback failed", []byte("ignored"), callbackErr, true},
		{"too large", []byte("replacement"), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Update(path, 8, func(old []byte) ([]byte, error) {
				if string(old) != string(keep) {
					t.Fatalf("callback read %q", old)
				}
				return tc.value, tc.err
			})
			if (err != nil) != tc.wantErr || (tc.err != nil && !errors.Is(err, tc.err)) {
				t.Fatalf("update returned %v", err)
			}
			got, err := Read(path, 8)
			if err != nil || string(got) != string(keep) {
				t.Fatalf("old file changed: %q, %v", got, err)
			}
		})
	}
	if got, err := Read(path, 7); err == nil || got != nil {
		t.Fatalf("over-limit read returned %q, %v", got, err)
	}
}

func TestMissingOrNonregularStateDoesNotCallEditor(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "not-a-file")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 64); err == nil {
		t.Fatal("state directory accepted as a file")
	}
	if err := Update(path, 64, func([]byte) ([]byte, error) { t.Fatal("called editor on invalid file"); return nil, nil }); err == nil {
		t.Fatal("updated a directory")
	}
	if err := EnsureDir(filepath.Join(root, "missing", "nested", "settings.json")); err == nil {
		t.Fatal("silent success creating state under missing parent")
	}
}

func TestImportLegacyKeepsStateCreatedDuringRecognition(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "custom.key")
	const name = "settings.json"
	legacy := filepath.Join(dir, name)
	path := Path(key, name)
	if err := os.WriteFile(legacy, []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := ImportLegacy(key, name, 32, func(raw []byte) bool {
		calls++
		if string(raw) != "legacy" {
			t.Fatalf("invalid legacy data: %q", raw)
		}
		if err := Update(path, 32, func([]byte) ([]byte, error) { return []byte("new local settings"), nil }); err != nil {
			t.Fatal(err)
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	current, err := Read(path, 32)
	if err != nil || string(current) != "new local settings" || calls != 1 {
		t.Fatalf("import overwrote new state: %q, %v, checks=%d", current, err, calls)
	}
	original, err := Read(legacy, 32)
	if err != nil || string(original) != "legacy" {
		t.Fatalf("legacy was changed: %q / %v", original, err)
	}
}

func TestIdentityStateFailedPathsDoNotCallEdit(t *testing.T) {
	dir := t.TempDir()
	const name = "settings.json"
	plainFile := filepath.Join(dir, "plain-file")
	if err := os.WriteFile(plainFile, []byte("original fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(plainFile, name), filepath.Join(dir, "directory-state", name)} {
		if filepath.Base(filepath.Dir(p)) == "directory-state" {
			if err := EnsureDir(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := Update(p, 32, func([]byte) ([]byte, error) {
			t.Fatalf("edit called for broken state path %q", p)
			return nil, nil
		}); err == nil {
			t.Fatalf("accepted broken state path %q", p)
		}
	}
	raw, err := os.ReadFile(plainFile)
	if err != nil || string(raw) != "original fixture" {
		t.Fatalf("update replaced unrelated file: %q / %v", raw, err)
	}
}

func TestImportLegacyRejectsDirectoryStateAndIgnoresRelativeKey(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "custom")
	const name = "settings.json"
	if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
		t.Fatal(err)
	}
	recognize := func([]byte) bool { t.Fatal("non-file legacy data reached recognition"); return false }
	if err := ImportLegacy(key, name, 32, recognize); err == nil {
		t.Fatal("legacy directory accepted")
	}
	if err := ImportLegacy("relative.key", name, 32, recognize); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(Path(key, name)); !os.IsNotExist(err) {
		t.Fatalf("a target was created: %v", err)
	}
}

func TestCustomStateFallsBackToPerIdentityWhenConfigHomeIsMissing(t *testing.T) {
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
		t.Skip("platform supplies an alternative config directory")
	}
	key := filepath.Join(t.TempDir(), "device.key")
	if got, want := Path(key, "settings.json"), filepath.Join(key+".peertty", "settings.json"); got != want {
		t.Fatalf("custom state escaped per-key layout: %q, want %q", got, want)
	}
}

func TestLegacyImportSkipsDefaultIdentityAndUnrecognizedMissingState(t *testing.T) {
	home := t.TempDir()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("APPDATA", home)
	case "darwin":
		t.Setenv("HOME", home)
	default:
		t.Setenv("XDG_CONFIG_HOME", home)
	}
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	const name = "settings.json"
	dir := filepath.Join(config, "PeerTTY")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte("already in current default layout")
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	defaultKey, custom := filepath.Join(dir, "device.key"), filepath.Join(t.TempDir(), "custom.key")
	for _, identity := range []string{defaultKey, custom} {
		if err := ImportLegacy(identity, name, 64, func([]byte) bool {
			t.Fatal("legacy importer touched current default layout or invented data")
			return false
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Read(Path(defaultKey, name), 64)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("default file unexpectedly changed: %q / %v", got, err)
	}
	if _, err := os.Stat(custom + ".peertty"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing legacy file created custom state: %v", err)
	}
}
