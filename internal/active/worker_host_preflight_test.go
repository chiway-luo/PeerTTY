package active

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"peertty/internal/grant"
	"peertty/internal/localssh"
)

func TestHostWorkerRequiresScopedPreflightOrPublishesExplicitFallback(t *testing.T) {
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	prepErr := errors.New("fixture scoped login preflight failed")
	for _, tc := range []struct {
		name          string
		requireScoped bool
		prepErr       error
	}{
		{"scoped refusal", true, prepErr},
		{"allowed system SSH fallback", false, prepErr},
		{"scoped host key and account advertised", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "session.offer")
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				deadline := time.Now().Add(time.Minute)
				w := &worker{Options: Options{PairingCode: fixtureCode, Role: "host", Port: 22, RequireScoped: tc.requireScoped},
					dir: dir, key: host, approval: make(chan grant.Ticket),
					state: State{PairingCode: fixtureCode, ID: "fixture", Role: "host", Phase: "gathering", Deadline: deadline},
				}
				p := &hostFixturePeer{controllerFixturePeer: controllerFixturePeer{ctx: ctx}}
				done := make(chan error, 1)
				var calls int
				go func() {
					done <- w.runWithLoginPrep(ctx, p, func(checkCtx context.Context) (*localssh.Login, error) {
						calls++
						if checkCtx != ctx {
							return nil, errors.New("wrong grant preflight context")
						}
						if tc.prepErr != nil {
							return nil, tc.prepErr
						}
						return &localssh.Login{User: "fixture-account", HostKey: hostPublic}, nil
					})
				}()
				synctest.Wait()
				if calls != 1 {
					t.Fatalf("expected one scoped preflight, observed %d", calls)
				}
				if tc.requireScoped && tc.prepErr != nil {
					err := <-done
					if !errors.Is(err, tc.prepErr) || !strings.Contains(err.Error(), "复查失败") || w.snapshot().Phase != "gathering" || !p.closed {
						t.Fatalf("required scoped preflight did not stop grant: %v / %+v", err, w.snapshot())
					}
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("invite escaped failed preflight: %v", err)
					}
					return
				}
				offer, err := grant.Read(path)
				st := w.snapshot()
				if err != nil || st.Phase != "waiting" || st.Exchange != path || !offer.Deadline().Equal(deadline) {
					t.Fatalf("preflight did not publish waiting state: %v / %+v", err, st)
				}
				if tc.prepErr == nil {
					if !bytes.Equal(offer.Claims.SSHHostKey, hostPublic) || offer.Claims.SSHUser != "fixture-account" || st.User != "fixture-account" || st.Note != "" {
						t.Fatalf("scoped invitation didn't bind local key/account: %+v", st)
					}
				} else if len(offer.Claims.SSHHostKey) != 0 || st.Note != tc.prepErr.Error() {
					t.Fatalf("unavailable scoped setup did not expose explicit fallback: %+v", st)
				}
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) || !p.closed || p.linked {
					t.Fatalf("unapproved session escaped shutdown: %v", err)
				}
			})
		})
	}
}
