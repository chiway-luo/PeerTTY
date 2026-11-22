package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestStdioCloseWriteDeliversEOFAndPreservesInput(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(inputPath, []byte("in"), 0600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	adapter := stdio{in: in, out: w}
	if n, err := io.WriteString(adapter, "out"); n != 3 || err != nil {
		t.Fatalf("write = %d, %v", n, err)
	}
	if err := adapter.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil || string(data) != "out" {
		t.Fatalf("output = %q, %v", data, err)
	}
	data, err = io.ReadAll(adapter)
	if err != nil || string(data) != "in" {
		t.Fatalf("input lost after half-close: %q, %v", data, err)
	}
	if err := adapter.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("close lost error: %v", err)
	}
	if _, err := adapter.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("input remained open: %v", err)
	}
}
