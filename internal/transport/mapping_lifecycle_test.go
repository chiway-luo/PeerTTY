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

func mappingResponse(req *stun.Message) *stun.Message {
	return stun.MustBuild(stun.NewTransactionIDSetter(req.TransactionID), stun.BindingSuccess,
		&stun.XORMappedAddress{IP: net.IPv4(192, 0, 2, 20), Port: 42000})
}

func TestDiscoveryRetryNeedsCurrentTransactionAndUsableMapping(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		server := netip.MustParseAddrPort("192.0.2.10:3478")
		udp := net.UDPAddrFromAddrPort(server)
		writes := make(chan netip.AddrPort, 16)
		base := &mappingFixtureUDP{source: udp, onWrite: func(addr net.Addr) { writes <- addr.(*net.UDPAddr).AddrPort() }}
		s := &gatheringSocket{UDPConn: base, ctx: ctx, signaling: &signalingNet{interval: time.Hour, retryDelay: time.Second}}
		old := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		current := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		for _, req := range []*stun.Message{old, current} {
			if _, err := s.WriteTo(req.Raw, udp); err != nil {
				t.Fatal(err)
			}
		}
		drainWrites(writes)
		id := stun.NewTransactionIDSetter(current.TransactionID)
		mapped := &stun.MappedAddress{IP: net.IPv4(192, 0, 2, 25), Port: 42000}
		for _, tc := range []struct {
			reply   *stun.Message
			src     *net.UDPAddr
			retries int
		}{
			{mappingResponse(old), udp, 1},
			{stun.MustBuild(id, stun.BindingSuccess), udp, 1},
			{stun.MustBuild(id, stun.BindingSuccess, &stun.XORMappedAddress{IP: net.IPv4zero, Port: 42000}), udp, 1},
			{mappingResponse(current), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.11:3478")), 1},
			{stun.MustBuild(id, stun.BindingSuccess, mapped), udp, 0},
		} {
			base.data, base.source = tc.reply.Raw, tc.src
			if _, _, err := s.ReadFrom(make([]byte, 256)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Second)
			synctest.Wait()
			if got := len(drainWrites(writes)); got != tc.retries {
				t.Fatalf("response from %v produced %d retries, want %d", tc.src, got, tc.retries)
			}
		}
	})
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
	resp := mappingResponse(req)
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

func drainWrites(ch chan netip.AddrPort) []netip.AddrPort {
	var out []netip.AddrPort
	for {
		select {
		case addr := <-ch:
			out = append(out, addr)
		default:
			return out
		}
	}
}

func TestGatheringDiscoveryRetriesUnconfirmedServers(t *testing.T) {
	first := netip.MustParseAddrPort("192.0.2.1:3478")
	second := netip.MustParseAddrPort("192.0.2.2:3478")
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	resp := mappingResponse(req)

	t.Run("confirmed before retry sends no extra probes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writes := make(chan netip.AddrPort, 16)
			base := &mappingFixtureUDP{
				data:   resp.Raw,
				source: net.UDPAddrFromAddrPort(first),
				onWrite: func(addr net.Addr) {
					writes <- addr.(*net.UDPAddr).AddrPort()
				},
			}
			signal := &signalingNet{interval: time.Hour, retryDelay: time.Second}
			s := &gatheringSocket{UDPConn: base, ctx: ctx, stop: cancel, signaling: signal, started: true}
			if _, err := s.WriteTo(req.Raw, net.UDPAddrFromAddrPort(first)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 128)
			if _, _, err := s.ReadFrom(buf); err != nil {
				t.Fatal(err)
			}
			// A retransmission of the same confirmed request needs no extra probes.
			if _, err := s.WriteTo(req.Raw, net.UDPAddrFromAddrPort(first)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(2 * time.Second)
			synctest.Wait()
			if got := drainWrites(writes); len(got) != 2 {
				t.Fatalf("expected only caller writes without retries, got %v", got)
			}
		})
	})

	t.Run("retries unconfirmed servers in order and stops when confirmed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writes := make(chan netip.AddrPort, 16)
			base := &mappingFixtureUDP{
				onWrite: func(addr net.Addr) {
					writes <- addr.(*net.UDPAddr).AddrPort()
				},
			}
			signal := &signalingNet{interval: time.Hour, retryDelay: time.Second}
			s := &gatheringSocket{UDPConn: base, ctx: ctx, stop: cancel, signaling: signal, started: true}
			_, _ = s.WriteTo(req.Raw, net.UDPAddrFromAddrPort(first))
			_, _ = s.WriteTo(req.Raw, net.UDPAddrFromAddrPort(second))
			drainWrites(writes)

			time.Sleep(time.Second)
			synctest.Wait()
			if got := drainWrites(writes); !slices.Equal(got, []netip.AddrPort{first, second}) {
				t.Fatalf("first retry batch = %v, want [%v %v]", got, first, second)
			}
			s.confirmServer(first, req.TransactionID)

			time.Sleep(time.Second)
			synctest.Wait()
			if got := drainWrites(writes); !slices.Equal(got, []netip.AddrPort{second}) {
				t.Fatalf("second retry batch = %v, want [%v]", got, second)
			}
			s.confirmServer(second, req.TransactionID)

			time.Sleep(2 * time.Second)
			synctest.Wait()
			if got := drainWrites(writes); len(got) != 0 {
				t.Fatalf("retries continued after all servers confirmed: %v", got)
			}
		})
	})

	t.Run("bounds retries for silent server", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writes := make(chan netip.AddrPort, 32)
			base := &mappingFixtureUDP{
				onWrite: func(addr net.Addr) {
					writes <- addr.(*net.UDPAddr).AddrPort()
				},
			}
			signal := &signalingNet{interval: time.Hour, retryDelay: time.Second}
			s := &gatheringSocket{UDPConn: base, ctx: ctx, stop: cancel, signaling: signal, started: true}
			_, _ = s.WriteTo(req.Raw, net.UDPAddrFromAddrPort(first))
			drainWrites(writes)
			time.Sleep(time.Duration(maxDiscoveryRetries+3) * time.Second)
			synctest.Wait()
			if got := drainWrites(writes); len(got) != maxDiscoveryRetries {
				t.Fatalf("retry count = %d, want %d", len(got), maxDiscoveryRetries)
			}
		})
	})

	t.Run("stops on cancel before tick and mid-batch", func(t *testing.T) {
		for _, midBatch := range []bool{false, true} {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				writes := make(chan netip.AddrPort, 16)
				base := &mappingFixtureUDP{
					onWrite: func(addr net.Addr) {
						dest := addr.(*net.UDPAddr).AddrPort()
						writes <- dest
						if midBatch && dest == first {
							cancel()
						}
					},
				}
				signal := &signalingNet{interval: time.Hour, retryDelay: time.Second}
				s := &gatheringSocket{
					UDPConn:   base,
					ctx:       ctx,
					stop:      cancel,
					signaling: signal,
					servers:   []netip.AddrPort{first, second},
					requests:  map[netip.AddrPort]discoveryRequest{first: {id: req.TransactionID, raw: req.Raw, retriesLeft: 1}, second: {id: req.TransactionID, raw: req.Raw, retriesLeft: 1}},
					started:   true,
					retrying:  true,
				}
				go s.retryDiscovery()
				synctest.Wait()
				if !midBatch {
					cancel()
					time.Sleep(2 * time.Second)
					synctest.Wait()
					if got := drainWrites(writes); len(got) != 0 {
						t.Fatalf("canceled socket sent discovery retries: %v", got)
					}
					return
				}
				time.Sleep(time.Second)
				synctest.Wait()
				if got := drainWrites(writes); !slices.Equal(got, []netip.AddrPort{first}) {
					t.Fatalf("mid-batch cancel sent unexpected writes: %v", got)
				}
			})
		}
	})
}
