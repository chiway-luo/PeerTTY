package localssh

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestOwnershipConfirmationRequiresMatchBeforeDeadline(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 15*time.Millisecond)
	defer stop()
	if err := waitForOwnedConnection(ctx, nil, nil, func() (bool, error) { return false, nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unconfirmed endpoint after deadline", err)
	}
	if err := waitForOwnedConnection(ctx, nil, nil, func() (bool, error) { return true, nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("accepted stale match", err)
	}
	if err := waitForOwnedConnection(t.Context(), nil, nil, func() (bool, error) { return true, nil }); err != nil {
		t.Fatal("rejected current match", err)
	}
}

type countedInput struct {
	bytes.Buffer
	closes int
}

func (c *countedInput) Close() error { c.closes++; return nil }

func TestTemporaryConnectionReleaseIsIdempotent(t *testing.T) {
	cause := errors.New("fixture worker stopped")
	input := new(countedInput)
	g := &guard{input: input, done: make(chan struct{}), err: cause}
	close(g.done)
	c := &Conn{guard: g, input: bufio.NewReader(strings.NewReader("buffered banner\r\n"))}
	if !c.Temporary() {
		t.Fatal("temporary connection lost ownership")
	}
	data, err := io.ReadAll(c)
	if err != nil || string(data) != "buffered banner\r\n" {
		t.Fatalf("read %q: %v", data, err)
	}
	for range 2 {
		if err := c.Release(); !errors.Is(err, cause) {
			t.Fatal("lost worker exit reason:", err)
		}
	}
	if input.closes != 1 {
		t.Fatalf("closed worker input %d times, want once", input.closes)
	}
}

func TestGuardHandshakeRequiresExpectedStatus(t *testing.T) {
	g := &guard{lines: make(chan string, 2)}
	g.lines <- "READY"
	g.lines <- "NOT ATTACHED"
	close(g.lines)
	if err := g.expect(t.Context(), "READY"); err != nil {
		t.Fatal(err)
	}
	if err := g.expect(t.Context(), "ATTACHED"); err == nil || !strings.Contains(err.Error(), "NOT ATTACHED") {
		t.Fatalf("lost unexpected worker response: %v", err)
	}
	if err := g.expect(t.Context(), "ATTACHED"); err == nil {
		t.Fatal("worker EOF treated as ready")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := (&guard{}).expect(ctx, "READY"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait: %v", err)
	}
}
