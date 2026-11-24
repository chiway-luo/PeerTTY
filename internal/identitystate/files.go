// Package identitystate stores mutable PeerTTY files separately for each device key.
package identitystate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"peertty/internal/filelock"
)

// Path preserves the installed default layout. An arbitrary -key may live in
// a directory shared with other identities and unrelated applications.
func Path(key, name string) string {
	if !filepath.IsAbs(key) {
		return ""
	}
	if config, err := os.UserConfigDir(); err == nil && key == filepath.Join(config, "PeerTTY", "device.key") {
		return filepath.Join(filepath.Dir(key), name)
	}
	return RuntimePath(key, name)
}

// Lookup by absolute profile path must also work for clients launched with a
// different config home (for example a second terminal using -key).
func RuntimePath(profile, name string) string {
	return filepath.Join(profile+".peertty", name)
}

func EnsureDir(path string) error {
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkDir(dir)
}

func checkDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("PeerTTY 状态路径不是目录: %s", dir)
	}
	return checkPermissions(dir, info)
}

func Read(path string, limit int64) ([]byte, error) {
	if err := checkDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("PeerTTY 状态文件不是普通文件: %s", path)
	}
	if err := checkPermissions(path, info); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("PeerTTY 状态文件在读取时已更换: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s 超过 %d 字节", path, limit)
	}
	return data, err
}

// ImportLegacy is used only when the user selected the old state directory
// explicitly. Copy recognized data once and leave both the original and any
// newer state intact. A bare -key never claims files in its parent directory.
func ImportLegacy(key, name string, limit int64, recognized func([]byte) bool) error {
	path := Path(key, name)
	legacy := filepath.Join(filepath.Dir(key), name)
	if path == "" || path == legacy {
		return nil
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(legacy); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	data, err := Read(legacy, limit)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !recognized(data) {
		return nil
	}
	return Update(path, limit, func(existing []byte) ([]byte, error) {
		if existing != nil {
			return nil, nil
		}
		return data, nil
	})
}

// Update serializes a read/modify/replace across menus and worker processes.
// A persistent lock file stays valid across atomic replacements of the data.
func Update(path string, limit int64, edit func([]byte) ([]byte, error)) error {
	if err := EnsureDir(path); err != nil {
		return err
	}
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		lock, err := filelock.Try(lockPath)
		if err == nil {
			defer lock.Close()
			break
		}
		if !errors.Is(err, filelock.ErrBusy) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, err := Read(path, limit)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err = edit(data)
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("%s 超过 %d 字节", path, limit)
	}
	return Replace(path, data)
}

// Replace publishes a complete owner-only file. The caller holds the lock
// protecting the corresponding state for the whole replacement.
func Replace(path string, data []byte) error {
	if err := EnsureDir(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".peertty-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, writeErr := tmp.Write(data)
	if err := errors.Join(writeErr, tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
