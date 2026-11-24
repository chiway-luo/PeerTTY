package identitystate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"peertty/internal/filelock"
)

func TestStateUpdateTimesOutWithoutTouchingContendedFile(t *testing.T) {
	path := Path(filepath.Join(t.TempDir(), "device.key"), "settings.json")
	if err := Update(path, 64, func([]byte) ([]byte, error) { return []byte("original"), nil }); err != nil {
		t.Fatal(err)
	}
	lock, err := filelock.Try(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	err = Update(path, 64, func([]byte) ([]byte, error) {
		t.Fatal("editor ran under a lock owned by another caller")
		return nil, nil
	})
	if !errors.Is(err, filelock.ErrBusy) {
		t.Fatalf("busy update returned %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "original" {
		t.Fatalf("contended update changed file: %q / %v", got, err)
	}
}
