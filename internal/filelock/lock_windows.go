package filelock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lock(f *os.File) error {
	// Lock a byte beyond the payload so read-only fingerprint display still works.
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &windows.Overlapped{OffsetHigh: 1})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrBusy
	}
	return err
}
