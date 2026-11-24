package grant

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestAdmissionCannotRegainElapsedGrantTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := clockSample{time.Now().Round(0), time.Hour}
		var sample atomic.Pointer[clockSample]
		sample.Store(&start)
		ctx, stop, err := withLifetime(t.Context(), start.wall.Add(time.Hour), start,
			func() (clockSample, error) { return *sample.Load(), nil })
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		link, cancel := context.WithCancel(ctx)
		defer cancel()
		sample.Store(&clockSample{start.wall.Add(45 * time.Minute), start.boot + time.Minute})
		if err := CheckLifetime(ctx); err != nil {
			t.Fatal(err)
		}
		// The wall clock rolls back after a forward step was already observed.
		sample.Store(&clockSample{start.wall.Add(-24 * time.Hour), start.boot + 15*time.Minute})
		if err := CheckLifetime(link); err != nil {
			t.Fatal("last authorized minute", err)
		}
		sample.Store(&clockSample{start.wall.Add(-24 * time.Hour), start.boot + 16*time.Minute})
		if err := CheckLifetime(link); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("expired link admission", err)
		}
		sample.Store(&start)
		if !errors.Is(CheckLifetime(ctx), context.DeadlineExceeded) {
			t.Fatal("returning the clocks to their opening values revived the grant")
		}
	})
}

func TestIdleGrantClosesAfterSuspendWithRolledBackWallClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := clockSample{time.Now(), time.Hour}
		var sample atomic.Pointer[clockSample]
		sample.Store(&start)
		ctx, stop, err := withLifetime(t.Context(), start.wall.Add(time.Hour), start, func() (clockSample, error) { return *sample.Load(), nil })
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		synctest.Wait()
		sample.Store(&clockSample{start.wall.Add(-time.Hour), start.boot + 2*time.Hour})
		time.Sleep(time.Second)
		synctest.Wait()
		if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			t.Fatal("background expiry did not close the idle connection", context.Cause(ctx))
		}
	})
}

func TestGrantClockFaultFailsClosed(t *testing.T) {
	start := clockSample{time.Now(), time.Hour}
	clockErr := errors.New("unavailable clock")
	for _, tc := range []struct {
		name string
		next clockSample
		err  error
	}{
		{"elapsed clock moved back", clockSample{start.wall, start.boot - time.Second}, nil},
		{"clock unavailable", start, clockErr},
		{"wall deadline reached", clockSample{start.wall.Add(time.Hour), start.boot}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, stop, err := withLifetime(t.Context(), start.wall.Add(time.Hour), start, func() (clockSample, error) { return tc.next, tc.err })
			if ctx != nil || stop != nil || err == nil || tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("invalid clock admitted a grant: %v", err)
			}
		})
	}
}
