package active

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/grant"
)

func TestWorkerStartReportsReadinessOrReason(t *testing.T) {
	for _, tc := range []struct {
		name               string
		result             reply
		readErr, cause     error
		canceled, timedOut bool
		message            string
	}{
		{name: "ready", result: reply{State: State{ID: "same-worker", Phase: "waiting"}}},
		{name: "declined", result: reply{Error: "fixture rejection"}, message: "fixture rejection"},
		{name: "lease already held", result: reply{Error: grant.ErrInUse.Error()}, cause: grant.ErrInUse},
		{name: "malformed startup frame", readErr: io.ErrUnexpectedEOF, cause: io.ErrUnexpectedEOF},
		{name: "startup timeout", timedOut: true, message: "启动超时"},
		{name: "start canceled", canceled: true, cause: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ready := make(chan error, 1)
			timeout := make(chan time.Time, 1)
			switch {
			case tc.canceled:
				cancel()
			case tc.timedOut:
				timeout <- time.Now()
			default:
				ready <- tc.readErr
			}
			got, err := awaitWorkerStart(ctx, timeout, ready, &tc.result)
			switch {
			case tc.cause != nil:
				if !errors.Is(err, tc.cause) || got.ID != "" {
					t.Fatalf("got %+v %v, want %v", got, err, tc.cause)
				}
			case tc.message != "":
				if err == nil || !strings.Contains(err.Error(), tc.message) || got.ID != "" {
					t.Fatalf("got %+v %v, want %q", got, err, tc.message)
				}
			default:
				if err != nil || got != tc.result.State {
					t.Fatalf("got %+v %v, want %+v", got, err, tc.result.State)
				}
			}
		})
	}
}

func TestWaitEndedObservesReplacementAndLeaseRelease(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	lease, err := grant.LeaseIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	ticks := make(chan time.Time, 3)
	for range cap(ticks) {
		ticks <- time.Now()
	}
	var calls int
	err = waitEnded(ctx, key, "old", ticks, func(context.Context) (State, error) {
		calls++
		switch calls {
		case 1:
			return State{ID: "old"}, nil
		case 2:
			return State{}, ErrInactive
		case 3:
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			return State{}, ErrInactive
		default:
			t.Fatal("unexpected status query")
			return State{}, nil
		}
	})
	if err != nil || calls != 3 {
		t.Fatalf("ended before lease release: calls=%d err=%v", calls, err)
	}
	lease2, err := grant.LeaseIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease2.Close()
	ticks <- time.Now()
	if err := waitEnded(ctx, key, "old", ticks, func(context.Context) (State, error) { return State{ID: "replacement"}, nil }); err != nil {
		t.Fatalf("replacement did not finish previous cleanup: %v", err)
	}
	cancel()
	if err := waitEnded(ctx, key, "old", nil, nil); err == nil || !strings.Contains(err.Error(), "后台仍在回收") {
		t.Fatalf("cancel lost cleanup state: %v", err)
	}
}

func TestWaitEndedReturnsLocalIdentityStorageError(t *testing.T) {
	asFile := filepath.Join(t.TempDir(), "not-directory")
	if err := os.WriteFile(asFile, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	err := waitEnded(ctx, filepath.Join(asFile, "device.key"), "old", ticks, func(context.Context) (State, error) { return State{}, ErrInactive })
	if err == nil || strings.Contains(err.Error(), "后台仍在回收") {
		t.Fatalf("discarded filesystem error: %v", err)
	}
}

type failedFrameWriter struct{ remaining int }

func (w *failedFrameWriter) Write(p []byte) (int, error) {
	if w.remaining == 0 {
		return 0, io.ErrClosedPipe
	}
	w.remaining--
	return len(p), nil
}

func TestLocalFrameWritesPropagateWriterFailures(t *testing.T) {
	for _, allowed := range []int{0, 1} {
		if err := send(&failedFrameWriter{remaining: allowed}, reply{State: State{ID: "fixture"}}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("write after %d successes returned %v", allowed, err)
		}
	}
}
