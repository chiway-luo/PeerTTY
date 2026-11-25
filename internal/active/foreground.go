package active

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"sync"

	"peertty/internal/grant"
)

// Foreground owns a single-use session's lease and its status/revoke endpoint.
// The session supplies the same lifetime context that guards its data stream.
type Foreground struct {
	profile       string
	mu            sync.Mutex // Serializes endpoint publication and lease release.
	lease         *grant.Lease
	owner         worker
	closeEndpoint func()
}

func ReserveForeground(profile, role string) (*Foreground, error) {
	lease, err := grant.LeaseIdentity(profile)
	if err != nil {
		return nil, err
	}
	state := State{ID: rand.Text(), Role: role, Phase: "gathering", OneShot: true}
	return &Foreground{profile: profile, lease: lease, owner: worker{state: state}}, nil
}

func (f *Foreground) Publish(ctx context.Context, cancel context.CancelFunc) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lease == nil {
		return ErrInactive
	}
	if f.closeEndpoint != nil {
		return grant.ErrInUse
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("单次会话缺少授权截止时间")
	}
	if err := grant.CheckLifetime(ctx); err != nil {
		return err
	}
	f.owner.update(func(s *State) { s.Deadline = deadline })
	closeEndpoint, err := serveControl(ctx, f.profile, func(c *tls.Conn) { f.owner.handle(ctx, c, cancel) })
	if err != nil {
		return err
	}
	f.closeEndpoint = closeEndpoint
	clearLastError(f.profile)
	return nil
}

func (f *Foreground) Progress(phase, device, route string) {
	f.owner.update(func(s *State) {
		s.Phase, s.Device, s.Route = phase, device, route
		if phase == "ready" {
			s.Terminals = 1
		}
	})
}

func (f *Foreground) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lease == nil {
		return nil
	}
	if f.closeEndpoint != nil {
		f.closeEndpoint()
	}
	err := f.lease.Close()
	f.lease = nil
	return err
}
