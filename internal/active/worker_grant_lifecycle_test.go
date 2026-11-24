package active

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pion/datachannel"
	"peertty/internal/grant"
)

type grantLifecyclePeer struct {
	controllerFixturePeer
	connected atomic.Bool
}

func (p *grantLifecyclePeer) Connected() bool { return p.connected.Load() }

type grantLifecycleFixture struct {
	controllerFixtureChannel
	replies chan string
	output  string
	text    bool
	until   time.Time
	err     error
}

func (s *grantLifecycleFixture) ReadDataChannel(buf []byte) (int, bool, error) {
	reply, ok := <-s.replies
	if !ok {
		return 0, false, io.EOF
	}
	return copy(buf, reply), true, nil
}
func (s *grantLifecycleFixture) WriteDataChannel(buf []byte, text bool) (int, error) {
	s.output, s.text = string(buf), text
	if s.err != nil {
		return 0, s.err
	}
	return len(buf), nil
}
func (s *grantLifecycleFixture) SetWriteDeadline(until time.Time) error {
	s.until = until
	return nil
}
func (s *grantLifecycleFixture) Close() error {
	close(s.replies)
	return s.controllerFixtureChannel.Close()
}

func TestControllerGrantRecoveryAndLocalEnd(t *testing.T) {
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, control, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"receipt", "no receipt", "stream write failed"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				offer, err := grant.NewLoginOffer(host, "fixture offer", "", nil, time.Now().Add(10*time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				w := &worker{Options: Options{PairingCode: fixtureCode, Role: "control", Key: filepath.Join(dir, "device.key"), Offer: offer},
					key: control, dir: dir, state: State{Phase: "gathering", Deadline: offer.Deadline()}}
				wire := &grantLifecycleFixture{replies: make(chan string)}
				if mode == "stream write failed" {
					wire.err = io.ErrClosedPipe
				}
				p := &grantLifecyclePeer{controllerFixturePeer: controllerFixturePeer{
					ctx:    t.Context(),
					answer: func(context.Context, string) (string, error) { return "fixture answer", nil },
					bind:   func([]byte) error { return nil },
					channel: func(context.Context) (datachannel.ReadWriteCloserDeadliner, string, error) {
						return wire, "fixture route", nil
					},
				}}
				p.connected.Store(true)
				done := make(chan error, 1)
				go func() { done <- w.runWithPeer(ctx, p) }()
				synctest.Wait()
				if state := w.snapshot(); state.Phase != "ready" {
					t.Fatalf("expected ready peer, got %+v", state)
				}
				if mode == "receipt" {
					currentLink := func() context.Context {
						w.mu.Lock()
						defer w.mu.Unlock()
						return w.linkCtx
					}
					loseRoute := func() {
						old := currentLink()
						p.connected.Store(false)
						time.Sleep(prolongedOutageWindow + 2*time.Second)
						synctest.Wait()
						if state := w.snapshot(); state.Phase != "disconnected" || state.Note != prolongedOutageText || old.Err() != context.Canceled {
							t.Fatalf("stalled links must close without ending the grant: state=%+v oldLink=%v", state, old.Err())
						}
					}
					recoverRoute := func(note string) {
						link := currentLink()
						p.connected.Store(true)
						time.Sleep(time.Second)
						synctest.Wait()
						if state := w.snapshot(); state.Phase != "ready" || state.Note != note || link.Err() != nil {
							t.Fatalf("wrong recovery state: state=%+v link=%v, expected note=%q", state, link.Err(), note)
						}
					}
					loseRoute()
					const other = "new status from another worker operation"
					w.update(func(s *State) { s.Note = other })
					recoverRoute(other)
					loseRoute()
					recoverRoute("")
				}
				start := time.Now()
				cancel()
				synctest.Wait()
				if wire.output != "REVOKE" || !wire.text || !wire.until.Equal(start.Add(time.Second)) {
					t.Fatalf("local end did not send a bounded revoke: %+v", wire)
				}
				var elapsed time.Duration
				if mode != "stream write failed" {
					select {
					case err := <-done:
						t.Fatalf("local end did not wait for a receipt or timeout: %v", err)
					default:
					}
					if mode == "receipt" {
						wire.replies <- "CLOSED"
					} else {
						elapsed = 3 * time.Second
					}
				}
				if err := <-done; !errors.Is(err, context.Canceled) || time.Since(start) != elapsed || !wire.closed || !p.closed {
					t.Fatalf("shutdown error=%v after %v, wire/peer closed=%v/%v", err, time.Since(start), wire.closed, p.closed)
				}
				synctest.Wait()
			})
		})
	}
}
