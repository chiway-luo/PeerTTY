package localssh

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
)

func TestOpenOnlyStartsTemporarySSHForRefusedStandardPort(t *testing.T) {
	unavailable := errors.New("fixture local network unavailable")
	startFailure := errors.New("fixture activation failed")
	for _, tc := range []struct {
		name                     string
		port                     int
		dialErr, want            error
		cancel, start, startFail bool
	}{
		{name: "standard port may activate", port: 22, dialErr: refused, start: true},
		{name: "pass on standard activation failure", port: 22, dialErr: refused, want: startFailure, start: true, startFail: true},
		{name: "custom port does not activate", port: 2222, dialErr: refused, want: refused},
		{name: "other error does not activate", port: 22, dialErr: unavailable, want: unavailable},
		{name: "expired grant does not activate", port: 22, dialErr: refused, want: refused, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			dials, starts := 0, 0
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tc.port))
			fixture := &Conn{}
			got, err := openWith(ctx, tc.port, func(gotCtx context.Context, gotAddr string) (*net.TCPConn, error) {
				dials++
				if gotAddr != addr || gotCtx != ctx {
					t.Fatalf("dial not scoped to selected loopback address/context: %q", gotAddr)
				}
				return nil, tc.dialErr
			}, func(gotCtx context.Context, gotAddr string) (*Conn, error) {
				starts++
				if gotAddr != addr || gotCtx != ctx {
					t.Fatalf("activation not scoped to selected loopback address/context: %q", gotAddr)
				}
				if tc.startFail {
					return nil, startFailure
				}
				return fixture, nil
			})
			if dials != 1 || starts > 1 || (starts == 1) != tc.start ||
				(got == fixture) != (tc.start && !tc.startFail) || !errors.Is(err, tc.want) {
				t.Fatalf("open=%p/%v, dials=%d, starts=%d", got, err, dials, starts)
			}
		})
	}
}
