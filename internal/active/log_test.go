package active

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"peertty/internal/identitystate"
)

func TestWorkerLogRotatesOnlyAfterLimit(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	path := LogPath(key)
	if err := identitystate.EnsureDir(path); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{maxWorkerLogSize, maxWorkerLogSize + 1} {
		before := bytes.Repeat([]byte{'x'}, size)
		if err := os.WriteFile(path, before, 0600); err != nil {
			t.Fatal(err)
		}
		f := openWorkerLog(key)
		if f == nil {
			t.Fatal("regular log was not opened")
		}
		_, writeErr := f.WriteString("fresh event\n")
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("log write: %v; close: %v", writeErr, closeErr)
		}
		if size > maxWorkerLogSize {
			before = nil
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, append(before, []byte("fresh event\n")...)) {
			t.Fatalf("rotation at %d bytes: got %d bytes, err %v", size, len(got), err)
		}
	}
}

func TestWorkerLogDeclinesNotRegular(t *testing.T) {
	key := filepath.Join(t.TempDir(), "id.key")
	path := LogPath(key)
	if err := identitystate.EnsureDir(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"relative.key", key} {
		if f := openWorkerLog(key); f != nil {
			f.Close()
			t.Fatal("invalid log path was opened")
		}
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("directory replaced while opening log: %v", err)
	}
	logWorkerEvent("device", "  \n")
}

func TestLastErrorFiltersOldOversizedAndIncompleteRecords(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	path := lastErrorPath(key)
	now := time.Now()
	tests := []struct {
		name string
		raw  string
		at   time.Time
	}{
		{name: "oversized", raw: string(bytes.Repeat([]byte{'x'}, lastErrorMaxBytes+1))},
		{name: "invalid JSON", raw: "not json"},
		{name: "empty reason", at: now},
		{name: "stale", at: now.Add(-lastErrorMaxAge - time.Minute)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.raw)
			if !tc.at.IsZero() {
				record := lastErrorRecord{At: tc.at}
				if tc.name == "stale" {
					record.Error = "old diagnostic"
				}
				var err error
				data, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if reason, at, ok := LastError(key); ok || reason != "" || !at.IsZero() {
				t.Fatalf("rejected record returned %q, %s, %v", reason, at, ok)
			}
		})
	}
	writeLastError(key, "  recent failure  ")
	writeLastError(key, "\t\n")
	writeLastError("relative", "not written")
	if reason, at, ok := LastError(key); !ok || at.Before(now) || reason != "recent failure" {
		t.Fatalf("blank record replaced recent reason: %q, %s, %v", reason, at, ok)
	}
	if reason, at, ok := LastError("relative"); ok || reason != "" || !at.IsZero() {
		t.Fatal("relative identities must not report a worker error")
	}
	clearLastError("relative")
	clearLastError(key)
	if _, _, ok := LastError(key); ok {
		t.Fatal("cleared diagnostic is still visible")
	}
}

func TestLastErrorWriteFailureDoesNotLeaveTempFile(t *testing.T) {
	dir := t.TempDir()
	writeLastError(filepath.Join(dir, "absent", "device.key"), "failed")
	key := filepath.Join(dir, "device.key")
	path := lastErrorPath(key)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	writeLastError(key, "failed")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) || !entries[0].IsDir() {
		t.Fatalf("diagnostic write left residue: %v", entries)
	}
}
