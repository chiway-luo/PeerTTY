package active

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"peertty/internal/identitystate"
)

const (
	maxWorkerLogSize  = 64 * 1024
	lastErrorMaxAge   = 15 * time.Minute
	lastErrorMaxBytes = 4096
)

// LogPath returns the diagnostic log for this device identity.
func LogPath(keyPath string) string {
	return identitystate.Path(keyPath, "worker.log")
}

func lastErrorPath(keyPath string) string {
	if !filepath.IsAbs(keyPath) {
		return ""
	}
	return keyPath + ".last-error"
}

func openWorkerLog(keyPath string) *os.File {
	path := LogPath(keyPath)
	if path == "" || identitystate.EnsureDir(path) != nil {
		return nil
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil
	}
	// The grant lease permits one writer. Seek to append instead of opening
	// append-only: Windows cannot truncate an append-only file handle.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil
	}
	if info.Size() > maxWorkerLogSize {
		err = f.Truncate(0)
	} else {
		_, err = f.Seek(0, io.SeekEnd)
	}
	if err != nil {
		f.Close()
		return nil
	}
	return f
}

func logWorkerEvent(id, event string) {
	if strings.TrimSpace(event) == "" {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "%s [%s] %s\n", time.Now().Format(time.RFC3339), id, strings.TrimSpace(event))
}

type lastErrorRecord struct {
	Error string    `json:"error"`
	At    time.Time `json:"at"`
}

func writeLastError(keyPath, reason string) {
	path := lastErrorPath(keyPath)
	if path == "" || strings.TrimSpace(reason) == "" {
		return
	}
	data, err := json.Marshal(lastErrorRecord{Error: strings.TrimSpace(reason), At: time.Now().UTC()})
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".peertty-err-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	_, wErr := tmp.Write(append(data, '\n'))
	if err := errors.Join(wErr, tmp.Close()); err != nil {
		_ = os.Remove(name)
		return
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
	}
}

func clearLastError(keyPath string) {
	if path := lastErrorPath(keyPath); path != "" {
		_ = os.Remove(path)
	}
}

// LastError returns the most recent abnormal background exit reason if it
// happened recently, helping users diagnose failures after the worker exits.
func LastError(keyPath string) (string, time.Time, bool) {
	path := lastErrorPath(keyPath)
	if path == "" {
		return "", time.Time{}, false
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > lastErrorMaxBytes {
		return "", time.Time{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", time.Time{}, false
	}
	var rec lastErrorRecord
	if err := json.Unmarshal(data, &rec); err != nil || rec.Error == "" {
		return "", time.Time{}, false
	}
	if time.Since(rec.At) > lastErrorMaxAge {
		return "", time.Time{}, false
	}
	return rec.Error, rec.At, true
}
