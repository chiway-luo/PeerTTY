// Package filelock takes nonblocking locks on existing local files.
package filelock

import (
	"errors"
	"os"
)

var ErrBusy = errors.New("file already locked")

func Try(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := lock(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
