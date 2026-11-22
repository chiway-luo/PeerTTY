//go:build !windows

package console

import (
	"os"

	"golang.org/x/sys/unix"
)

func (k *receiptKeys) poll(in *os.File) (string, bool, error) {
	fds := []unix.PollFd{{Fd: int32(in.Fd()), Events: unix.POLLIN}}
	return k.readAvailable(in, func() (bool, error) {
		n, err := unix.Poll(fds, 0)
		if err == unix.EINTR {
			return false, nil
		}
		return n > 0, err
	})
}
