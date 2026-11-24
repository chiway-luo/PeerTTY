package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestRoamingPathChecksRespectRetryWindowAndGrantLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r, _ := roamingPair(t, ctx)
	udp := &socketLifecycleFixture{}
	sock := &roamSocket{UDPConn: udp}
	path := wirePath{sock, netip.MustParseAddrPort("127.0.0.1:13001")}
	t0 := time.Now()
	r.confirmed[path] = t0.Add(-time.Second)
	r.challenge(path, t0)
	if udp.writes != 0 || len(r.challenges) != 0 {
		t.Fatal("recently confirmed path was probed again")
	}
	initialAt := t0.Add(time.Second)
	r.challenge(path, initialAt)
	initial := r.challenges[path]
	if udp.writes != 1 || initial.issued != initialAt || initial.sent != initialAt {
		t.Fatalf("first route check = %+v, writes=%d", initial, udp.writes)
	}
	r.challenge(path, initialAt.Add(time.Second))
	if r.challenges[path] != initial || udp.writes != 1 {
		t.Fatal("retry before minimum interval changed pending check")
	}
	retryAt := initialAt.Add(2 * time.Second)
	r.challenge(path, retryAt)
	retry := r.challenges[path]
	if retry.token != initial.token || retry.issued != initialAt || retry.sent != retryAt || udp.writes != 2 {
		t.Fatalf("pending check was not retried consistently: %+v, writes=%d", retry, udp.writes)
	}
	renewAt := initialAt.Add(pathLifetime)
	r.challenge(path, renewAt)
	renewed := r.challenges[path]
	if renewed.issued != renewAt || renewed.sent != renewAt || udp.writes != 3 {
		t.Fatalf("expired check did not get a fresh window: %+v, writes=%d", renewed, udp.writes)
	}
	cancel()
	r.challenge(path, renewAt.Add(pathLifetime))
	if r.challenges[path] != renewed || udp.writes != 3 {
		t.Fatal("ending the grant did not stop route checks")
	}
}

func TestRoamingSearchPrunesExpiredStateAndStopsOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		r, _ := roamingPair(t, ctx)
		defer r.close()
		udp := &socketLifecycleFixture{}
		sock := &roamSocket{UDPConn: udp}
		old := wirePath{sock, netip.MustParseAddrPort("127.0.0.1:13002")}
		newer := wirePath{sock, netip.MustParseAddrPort("127.0.0.1:13003")}
		now := time.Now()
		r.challenges[old] = routeChallenge{issued: now.Add(-pathLifetime)}
		r.challenges[newer] = routeChallenge{issued: now}
		r.confirmed[old], r.confirmed[newer] = now.Add(-2*time.Minute), now
		ended := make(chan struct{})
		go func() {
			defer close(ended)
			r.search(func() bool { return false })
		}()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		r.mu.Lock()
		_, keptOldChallenge := r.challenges[old]
		_, keptNewChallenge := r.challenges[newer]
		_, keptOldProof := r.confirmed[old]
		_, keptNewProof := r.confirmed[newer]
		r.mu.Unlock()
		if keptOldChallenge || keptOldProof || !keptNewChallenge || !keptNewProof || udp.writes != 0 {
			t.Fatal("search did not prune just the expired, unused state")
		}
		cancel()
		synctest.Wait()
		select {
		case <-ended:
			t.Fatal("search disposed of the grant before the owner closed it")
		default:
		}
		r.close()
		<-ended
	})
}

type routeSearchFixture struct {
	socketLifecycleFixture
	mu    sync.Mutex
	dests []netip.AddrPort
}

func (s *routeSearchFixture) WriteTo(data []byte, dst net.Addr) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dests = append(s.dests, dst.(*net.UDPAddr).AddrPort())
	return s.socketLifecycleFixture.WriteTo(data, dst)
}

func (s *routeSearchFixture) targets() []netip.AddrPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.dests)
}

func TestRoamingSearchUsesBoundedCandidateBatchesAndClosesOnlySpares(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		r, _ := roamingPair(t, ctx)
		defer r.close()
		main, v4, v6 := &routeSearchFixture{}, &routeSearchFixture{}, &routeSearchFixture{}
		logical := netip.MustParseAddrPort("192.0.2.10:13000")
		loop := netip.MustParseAddrPort("127.0.0.1:13000")
		six := netip.MustParseAddrPort("[2001:db8::1]:13000")
		makeSock := func(f *routeSearchFixture) *roamSocket {
			return &roamSocket{UDPConn: f, done: make(chan struct{})}
		}
		r.logical = wirePath{makeSock(main), logical}
		r.targets = []netip.AddrPort{logical, loop, six}
		for i := range 14 {
			r.targets = append(r.targets, netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(20 + i)}), 13000))
		}
		last := r.targets[len(r.targets)-1]
		var opens []string
		var opensMu sync.Mutex
		opened := func() []string {
			opensMu.Lock()
			defer opensMu.Unlock()
			return slices.Clone(opens)
		}
		failSix := true
		done := make(chan struct{})
		go func() {
			defer close(done)
			r.searchWith(func() bool { return false }, func(network string) (*roamSocket, error) {
				opensMu.Lock()
				opens = append(opens, network)
				opensMu.Unlock()
				if network == "udp4" {
					return makeSock(v4), nil
				}
				if failSix {
					failSix = false
					return nil, errors.New("temporary unavailable IPv6 fixture")
				}
				return makeSock(v6), nil
			})
		}()
		synctest.Wait()
		time.Sleep(6500 * time.Millisecond)
		synctest.Wait()
		if len(opened()) != 0 || len(main.targets()) != 0 {
			t.Fatal("recovery bypassed initial checklist grace period")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if !slices.Equal(opened(), []string{"udp4", "udp6"}) || !slices.Equal(main.targets(), v4.targets()) || len(main.targets()) != 14 ||
			slices.Contains(main.targets(), loop) || slices.Contains(main.targets(), six) || slices.Contains(main.targets(), last) {
			t.Fatalf("first batch leaked, duplicated, or exceeded its limit: opens=%v logical=%v spare=%v", opened(), main.targets(), v4.targets())
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if !slices.Equal(opened(), []string{"udp4", "udp6", "udp6"}) || !slices.Contains(main.targets(), last) ||
			!slices.Contains(v4.targets(), last) || !slices.Equal(v6.targets(), []netip.AddrPort{six}) {
			t.Fatalf("next batch did not rotate or restore IPv6 correctly: opens=%v v4=%v v6=%v", opened(), v4.targets(), v6.targets())
		}
		r.close()
		<-done
		if main.closes != 0 || v4.closes != 1 || v6.closes != 1 {
			t.Fatalf("search closed wrong sockets: logical=%d ipv4=%d ipv6=%d", main.closes, v4.closes, v6.closes)
		}
	})
}

func TestRoamingSearchRevalidatesPhysicalEgressWhileICEReportsUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, _ := roamingPair(t, t.Context())
		defer r.close()
		main, physical, spare := &routeSearchFixture{}, &routeSearchFixture{}, &routeSearchFixture{}
		makeSock := func(f *routeSearchFixture) *roamSocket {
			return &roamSocket{UDPConn: f, done: make(chan struct{})}
		}
		logical := netip.MustParseAddrPort("192.0.2.10:13000")
		moved := netip.MustParseAddrPort("192.0.2.11:13000")
		r.logical = wirePath{makeSock(main), logical}
		r.physical = wirePath{makeSock(physical), moved}
		r.lastProof = time.Now()
		r.confirmed[r.physical] = r.lastProof.Add(-2 * time.Minute)
		done := make(chan struct{})
		go func() {
			defer close(done)
			r.searchWith(func() bool { return true }, func(_ string) (*roamSocket, error) {
				return makeSock(spare), nil
			})
		}()
		synctest.Wait()
		time.Sleep(2500 * time.Millisecond)
		synctest.Wait()
		r.mu.Lock()
		proof := r.confirmed[r.physical]
		r.mu.Unlock()
		if !slices.Equal(physical.targets(), []netip.AddrPort{moved}) || len(main.targets()) != 0 || len(spare.targets()) != 0 || proof.IsZero() {
			t.Fatal("healthy path was not revalidated in place")
		}
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if len(physical.targets()) != 3 || !slices.Equal(main.targets(), []netip.AddrPort{moved, logical}) ||
			!slices.Equal(spare.targets(), []netip.AddrPort{moved, logical}) {
			t.Fatalf("stale physical egress did not search alternatives: physical=%v original=%v spare=%v", physical.targets(), main.targets(), spare.targets())
		}
		r.close()
		<-done
	})
}
