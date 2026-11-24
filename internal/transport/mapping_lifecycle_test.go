package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5"
)

type mappingFixtureUDP struct {
	transport.UDPConn
	data    []byte
	source  net.Addr
	readErr error
	onWrite func(net.Addr)
}

func (s *mappingFixtureUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	return copy(p, s.data), s.source, s.readErr
}

func (s *mappingFixtureUDP) WriteTo(p []byte, dst net.Addr) (int, error) {
	if s.onWrite != nil {
		s.onWrite(dst)
	}
	return len(p), nil
}

func TestGatheringSocketTracksOnlyValidDiscoveryAndConfirmationEndpoints(t *testing.T) {
	live := netip.MustParseAddrPort("192.0.2.1:3478")
	backup := netip.MustParseAddrPort("192.0.2.2:3478")
	tcp := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3478}
	unset := &net.UDPAddr{}
	good := net.UDPAddrFromAddrPort(live)
	base := &mappingFixtureUDP{}
	s := &gatheringSocket{UDPConn: base, started: true}
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	resp := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
	for _, destination := range []net.Addr{tcp, unset, good, net.UDPAddrFromAddrPort(backup)} {
		n, err := s.WriteTo(req.Raw, destination)
		if n != len(req.Raw) || err != nil {
			t.Fatalf("wrapper changed result for %v: %d, %v", destination, n, err)
		}
	}
	if targets := s.refreshTargets(); !slices.Equal(targets, []netip.AddrPort{live, backup}) {
		t.Fatalf("discovery tracked invalid or wrong-family addresses: %v", targets)
	}
	readErr := errors.New("fixture read failure")
	for _, tc := range []struct {
		data []byte
		src  net.Addr
		err  error
	}{
		{resp.Raw, good, readErr},
		{nil, good, nil},
		{[]byte("ordinary application packet"), good, nil},
		{req.Raw, good, nil},
		{resp.Raw, tcp, nil},
		{resp.Raw, unset, nil},
		{resp.Raw, good, nil},
	} {
		base.data, base.source, base.readErr = tc.data, tc.src, tc.err
		buf := make([]byte, 256)
		n, from, err := s.ReadFrom(buf)
		if n != len(tc.data) || from != tc.src || err != tc.err || !slices.Equal(buf[:n], tc.data) {
			t.Fatalf("refresh wrapper changed a read result: %d / %v / %v", n, from, err)
		}
		want := []netip.AddrPort{live, backup}
		if err == nil && from == good && slices.Equal(tc.data, resp.Raw) {
			want = want[:1]
		}
		if targets := s.refreshTargets(); !slices.Equal(targets, want) {
			t.Fatalf("older valid server displaced by an unrelated read: %v vs %v", targets, want)
		}
	}
}

func TestGatheringRefreshStopsBeforeOtherEndpointsWhenGrantIsCanceled(t *testing.T) {
	for _, phase := range []string{"servers", "peers", "no peer destinations", "no servers"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				server := netip.MustParseAddrPort("192.0.2.1:3478")
				other := netip.MustParseAddrPort("192.0.2.2:3478")
				peer := netip.MustParseAddrPort("192.0.2.9:43000")
				nextPeer := netip.MustParseAddrPort("192.0.2.10:43000")
				writes := make(chan netip.AddrPort, 8)
				done := make(chan struct{})
				signal := &signalingNet{interval: time.Second}
				targets := []netip.AddrPort{server, other}
				want := []netip.AddrPort{server}
				peers := []netip.AddrPort{peer, nextPeer}
				switch phase {
				case "peers":
					want = []netip.AddrPort{server, other, peer}
					signal.remote.Store(&peers)
				case "no peer destinations":
					targets = []netip.AddrPort{server}
					signal.remote.Store(&[]netip.AddrPort{})
				case "no servers":
					targets, want = nil, nil
					signal.remote.Store(&peers)
				default:
					signal.remote.Store(&peers)
				}
				s := &gatheringSocket{ctx: ctx, signaling: signal, servers: targets,
					UDPConn: &mappingFixtureUDP{onWrite: func(addr net.Addr) {
						dest := addr.(*net.UDPAddr).AddrPort()
						writes <- dest
						if (phase == "servers" && dest == server) || (phase == "peers" && dest == peer) {
							cancel()
						}
					}}}
				go func() { defer close(done); s.refresh() }()
				synctest.Wait()
				time.Sleep(1100 * time.Millisecond)
				synctest.Wait()
				cancel()
				<-done
				close(writes)
				var got []netip.AddrPort
				for dest := range writes {
					got = append(got, dest)
				}
				if !slices.Equal(got, want) {
					t.Fatalf("late or unexpected writes during refresh: %v vs %v", got, want)
				}
			})
		})
	}
}
