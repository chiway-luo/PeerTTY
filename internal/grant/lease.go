package grant

import (
	"errors"
	"os"

	"peertty/internal/filelock"
)

var ErrInUse = errors.New("此设备已有一份授权，请先结束当前会话")

// LeaseIdentity locks the key file for either role. The OS releases the lease
// when the handle closes, including when the process terminates.
func LeaseIdentity(path string) (*os.File, error) {
	f, err := filelock.Try(path)
	if errors.Is(err, filelock.ErrBusy) {
		return nil, ErrInUse
	}
	return f, err
}
