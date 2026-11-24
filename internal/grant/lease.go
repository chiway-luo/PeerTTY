package grant

import (
	"errors"
	"os"
	"path/filepath"

	"peertty/internal/filelock"
	"peertty/internal/identitystate"
)

var ErrInUse = errors.New("此设备已有一份授权，请先结束当前会话")

type Lease struct{ slot, legacy *os.File }

func (l *Lease) Close() error {
	var err error
	if l.legacy != nil {
		err = l.legacy.Close()
	}
	return errors.Join(err, l.slot.Close())
}

// A profile needs only an empty lock file. Also honor an older binary's lock
// when upgrading a profile that already contains a device key.
func LeaseIdentity(path string) (*Lease, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	slot := identitystate.RuntimePath(path, "grant.lock")
	if err := identitystate.EnsureDir(slot); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(slot, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	f, err = filelock.Try(slot)
	if errors.Is(err, filelock.ErrBusy) {
		return nil, ErrInUse
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Lease{slot: f}, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("旧设备配置路径应为普通文件")
	}
	legacy, err := filelock.Try(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		f.Close()
		if errors.Is(err, filelock.ErrBusy) {
			return nil, ErrInUse
		}
		return nil, err
	}
	return &Lease{slot: f, legacy: legacy}, nil
}
