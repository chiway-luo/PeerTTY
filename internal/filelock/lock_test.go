package filelock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExclusiveLockPreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	if f, err := Try(path); f != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing path: %v, %v", f, err)
	}
	if err := os.WriteFile(path, []byte("identity"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := Try(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if f, err := Try(path); f != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("competing lock: %v, %v", f, err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "identity" {
		t.Fatalf("locked contents: %q %v", data, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Try(path)
	if err != nil {
		t.Fatalf("release did not free lock: %v", err)
	}
	next.Close()
}
