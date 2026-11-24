//go:build darwin || linux

package identitystate

import (
	"errors"
	"os"
	"path/filepath"
)

func durableRename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	// The per-profile directory itself may have been created for this grant.
	dir := filepath.Dir(to)
	for _, path := range []string{dir, filepath.Dir(dir)} {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		if err := errors.Join(f.Sync(), f.Close()); err != nil {
			return err
		}
	}
	return nil
}
