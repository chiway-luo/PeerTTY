//go:build darwin || linux

package console

import (
	"os"

	"golang.org/x/sys/unix"
)

// OpenSSH can leave a shared stdin pipe nonblocking after an abrupt disconnect.
// Restore just that flag so the menu can continue reading the same input.
func keepSSHInput(in *os.File) (func() error, error) {
	fd := in.Fd()
	flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil {
		return nil, err
	}
	return func() error { return unix.SetNonblock(int(fd), flags&unix.O_NONBLOCK != 0) }, nil
}
