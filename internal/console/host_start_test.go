package console

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/localssh"
)

func TestHostStartupRevalidatesSSHBeforeStartingGrant(t *testing.T) {
	problem := errors.New("fixture unavailable")
	for _, tc := range []struct {
		name, role, failAt, wantCalls string
		wantErr                       error
	}{
		{"already hosting", "host", "", "sw", nil},
		{"already controlling", "control", "", "s", grant.ErrInUse},
		{"status unavailable", "", "s", "s", problem},
		{"initial SSH unavailable", "", "r", "sr", problem},
		{"user exits duration prompt", "", "d", "srd", errBack},
		{"SSH becomes unavailable during duration prompt", "", "R", "srdR", problem},
		{"worker startup fails", "", "a", "srdRa", problem},
		{"start and watch exact new grant", "", "", "srdRaw", nil},
		{"watch reports worker ended", "", "w", "srdRaw", problem},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Console{Settings: Settings{KeyPath: "fixture-key", SSHPort: 22, STUN: "none"}, out: io.Discard}
			const ttl = 12 * time.Minute
			var calls strings.Builder
			deps := hostStartServices{
				status: func(_ context.Context, key string) (active.State, error) {
					calls.WriteByte('s')
					if key != c.KeyPath {
						t.Fatalf("wrong key: %q", key)
					}
					if tc.failAt == "s" {
						return active.State{}, problem
					}
					if tc.role != "" {
						return active.State{ID: "existing", Role: tc.role}, nil
					}
					return active.State{}, active.ErrInactive
				},
				ready: func(context.Context) (localssh.Check, error) {
					if calls.String() == "s" {
						calls.WriteByte('r')
						if tc.failAt == "r" {
							return localssh.Check{}, problem
						}
						return localssh.Check{Ready: true}, nil
					}
					calls.WriteByte('R')
					if tc.failAt == "R" {
						return localssh.Check{}, problem
					}
					return localssh.Check{Ready: true, ScopedOnly: true}, nil
				},
				duration: func(_ context.Context, initial localssh.Check) (time.Duration, error) {
					calls.WriteByte('d')
					if !initial.Ready || initial.ScopedOnly {
						t.Fatalf("wrong initial listener state: %+v", initial)
					}
					if tc.failAt == "d" {
						return 0, errBack
					}
					return ttl, nil
				},
				start: func(_ context.Context, o active.Options) (active.State, error) {
					calls.WriteByte('a')
					if o.Role != "host" || o.Key != c.KeyPath || o.Port != c.SSHPort || o.STUN != c.STUN || o.TTL != ttl || !o.RequireScoped {
						t.Fatalf("worker did not receive latest scoped policy/user duration: %+v", o)
					}
					if tc.failAt == "a" {
						return active.State{}, problem
					}
					return active.State{ID: "started", Role: "host"}, nil
				},
				watch: func(_ context.Context, s active.State) error {
					calls.WriteByte('w')
					wantID := "started"
					if tc.role == "host" {
						wantID = "existing"
					}
					if s.ID != wantID || s.Role != "host" {
						t.Fatalf("watched wrong grant: %+v", s)
					}
					if tc.failAt == "w" {
						return problem
					}
					return nil
				},
			}
			if err := c.hostWith(t.Context(), deps); !errors.Is(err, tc.wantErr) || calls.String() != tc.wantCalls {
				t.Fatalf("err=%v calls=%s; want %v and %s", err, calls.String(), tc.wantErr, tc.wantCalls)
			}
		})
	}
}
