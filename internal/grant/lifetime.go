package grant

import (
	"context"
	"errors"
	"sync"
	"time"
)

type clockSample struct {
	wall time.Time
	boot time.Duration // Includes system suspend on the supported platforms.
}

func systemClock() (clockSample, error) {
	boot, err := timeSinceBoot()
	return clockSample{wall: time.Now(), boot: boot}, err
}

type lifetimeKey struct{}

type lifetime struct {
	mu        sync.Mutex
	read      func() (clockSample, error)
	expires   time.Time // Signed wall deadline, without a Go monotonic reading.
	lastBoot  time.Duration
	remaining time.Duration
	cancel    context.CancelCauseFunc
}

// WithLifetime bounds a grant by both its wall deadline and elapsed time.
// Its deadline remains available to OpenSSH and ICE through derived contexts.
func WithLifetime(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc, error) {
	start, err := systemClock()
	if err != nil {
		return nil, nil, err
	}
	return withLifetime(parent, deadline, start, systemClock)
}

func withLifetime(parent context.Context, deadline time.Time, start clockSample, read func() (clockSample, error)) (context.Context, context.CancelFunc, error) {
	if err := context.Cause(parent); err != nil {
		return nil, nil, err
	}
	expires := deadline.Round(0)
	left := min(MaxTTL, deadline.Sub(start.wall), expires.Sub(start.wall))
	if left <= 0 {
		return nil, nil, context.DeadlineExceeded
	}
	timer, stop := context.WithDeadline(parent, start.wall.Add(left))
	ctx, cancel := context.WithCancelCause(timer)
	g := &lifetime{read: read, expires: expires, lastBoot: start.boot, remaining: left, cancel: cancel}
	ctx = context.WithValue(ctx, lifetimeKey{}, g)
	closeGrant := func() { cancel(context.Canceled); stop() }
	left = g.check()
	if err := context.Cause(ctx); err != nil {
		closeGrant()
		return nil, nil, err
	}
	go g.watch(ctx, left)
	return ctx, closeGrant, nil
}

// CheckLifetime also checks the clocks synchronously at admission, including
// on the first request after wakeup before the background timer has run.
func CheckLifetime(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if g, ok := ctx.Value(lifetimeKey{}).(*lifetime); ok {
		g.check()
	}
	return context.Cause(ctx)
}

// Remaining reports the enforced budget for status snapshots and local SSH
// helpers. An ordinary context has no separate grant budget.
func Remaining(ctx context.Context) (time.Duration, bool) {
	g, ok := ctx.Value(lifetimeKey{}).(*lifetime)
	if !ok || ctx.Err() != nil {
		return 0, ok
	}
	return g.check(), true
}

func (g *lifetime) check() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	now, err := g.read()
	if err == nil && now.boot < g.lastBoot {
		err = errors.New("系统运行计时异常，请重新配对")
	}
	if err == nil {
		// A forward wall step can shorten the remaining budget. A later
		// backward step cannot give any of that time back.
		g.remaining = min(g.remaining-(now.boot-g.lastBoot), g.expires.Sub(now.wall.Round(0)))
		g.lastBoot = now.boot
		if g.remaining > 0 {
			return g.remaining
		}
		err = context.DeadlineExceeded
	}
	g.cancel(err)
	return 0
}

func (g *lifetime) watch(ctx context.Context, left time.Duration) {
	timer := time.NewTimer(min(time.Second, left))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			left = g.check()
			if left <= 0 {
				return
			}
			timer.Reset(min(time.Second, left))
		}
	}
}
