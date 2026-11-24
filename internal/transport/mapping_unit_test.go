package transport

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5"
)

type recordedDatagram struct {
	to   netip.AddrPort
	kind stun.MessageType
}

type memoryUDP struct {
	transport.UDPConn
	writes chan recordedDatagram
	closed bool
}

func (c *memoryUDP) WriteTo(data []byte, addr net.Addr) (int, error) {
	if len(data) == 0 {
		return 0, errors.New("fixture write failure")
	}
	msg := &stun.Message{Raw: data}
	_ = msg.Decode()
	select {
	case c.writes <- recordedDatagram{addr.(*net.UDPAddr).AddrPort(), msg.Type}:
	default:
	}
	return len(data), nil
}

func (c *memoryUDP) Close() error { c.closed = true; return nil }

type memoryNet struct {
	transport.Net
	conn *memoryUDP
}

func (n memoryNet) ListenUDP(_ string, _ *net.UDPAddr) (transport.UDPConn, error) {
	return n.conn, nil
}

func TestGatheringSocketRefreshesOnlyMappedPeersOfItsAddressFamily(t *testing.T) {
	v4 := netip.MustParseAddrPort("192.0.2.7:2345")
	v6 := netip.MustParseAddrPort("[2001:db8::7]:2345")
	stunAddr := netip.MustParseAddrPort("192.0.2.1:3478")
	base := &memoryUDP{writes: make(chan recordedDatagram, 12)}
	n := &signalingNet{Net: memoryNet{conn: base}, ctx: t.Context(), interval: 5 * time.Millisecond}
	peers := []netip.AddrPort{v6, v4}
	n.remote.Store(&peers)
	raw, err := n.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := raw.(*gatheringSocket)
	server := net.UDPAddrFromAddrPort(stunAddr)
	if _, err := c.WriteTo(nil, server); err == nil {
		t.Fatal("underlying write failure was hidden")
	}
	req := stun.MustBuild(stun.BindingRequest, stun.TransactionID)
	if n, err := c.WriteTo(req.Raw, server); err != nil || n != len(req.Raw) {
		t.Fatalf("binding write: %d, %v", n, err)
	}
	until := time.NewTimer(time.Second)
	defer until.Stop()
	indication := stun.NewType(stun.MethodBinding, stun.ClassIndication)
	for _, want := range []recordedDatagram{{stunAddr, stun.BindingRequest}, {stunAddr, indication}, {v4, indication}} {
		select {
		case got := <-base.writes:
			if got != want {
				t.Fatalf("datagram %+v, want %+v", got, want)
			}
		case <-until.C:
			t.Fatalf("missing datagram %+v", want)
		}
	}
	if err := c.Close(); err != nil || !base.closed || c.ctx.Err() == nil {
		t.Fatalf("closing did not stop discovery: %v", err)
	}
}

type mockReadWriteUDP struct {
	memoryUDP
	readData []byte
	readFrom net.Addr
}

func (c *mockReadWriteUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	n := copy(p, c.readData)
	return n, c.readFrom, nil
}

func TestGatheringSocketIgnoresNonDiscoveryAndPrioritizesConfirmedSTUN(t *testing.T) {
	dead := netip.MustParseAddrPort("192.0.2.1:3478")
	live := netip.MustParseAddrPort("192.0.2.2:19302")
	resp := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
	base := &mockReadWriteUDP{
		memoryUDP: memoryUDP{writes: make(chan recordedDatagram, 20)},
		readData:  resp.Raw,
		readFrom:  net.UDPAddrFromAddrPort(live),
	}
	n := &signalingNet{Net: memoryNet{conn: &base.memoryUDP}, ctx: t.Context(), interval: 10 * time.Millisecond}
	c := &gatheringSocket{UDPConn: base, ctx: t.Context(), stop: func() {}, signaling: n}

	// Non-STUN packet first must not disarm subsequent STUN discovery refresh.
	if _, err := c.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(dead)); err != nil {
		t.Fatal(err)
	}
	// Authenticated ICE binding request must also be ignored for server tracking.
	iceReq := stun.MustBuild(stun.BindingRequest, stun.TransactionID, stun.NewUsername("u:p"))
	if _, err := c.WriteTo(iceReq.Raw, net.UDPAddrFromAddrPort(dead)); err != nil {
		t.Fatal(err)
	}
	if len(c.refreshTargets()) != 0 {
		t.Fatalf("tracked non-discovery packet as STUN server: %v", c.refreshTargets())
	}

	req := stun.MustBuild(stun.BindingRequest, stun.TransactionID)
	_, _ = c.WriteTo(req.Raw, net.UDPAddrFromAddrPort(dead))
	_, _ = c.WriteTo(req.Raw, net.UDPAddrFromAddrPort(live))
	buf := make([]byte, 128)
	if _, _, err := c.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	got := c.refreshTargets()
	if len(got) != 1 || got[0] != live {
		t.Fatalf("refreshTargets() = %v, want only confirmed [%v]", got, live)
	}
}

type fixtureBindNet struct {
	transport.Net
	conn transport.UDPConn
	err  error
}

func (n fixtureBindNet) ListenUDP(string, *net.UDPAddr) (transport.UDPConn, error) {
	return n.conn, n.err
}

func TestSignalingWrapsOnlyWildcardBinds(t *testing.T) {
	raw := &memoryUDP{}
	n := &signalingNet{Net: fixtureBindNet{conn: raw}, ctx: t.Context(), interval: time.Hour}
	for _, tc := range []struct {
		name    string
		addr    *net.UDPAddr
		wrapped bool
	}{
		{"empty address", &net.UDPAddr{}, true},
		{"any IPv4", &net.UDPAddr{IP: net.IPv4zero}, true},
		{"explicit address", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := n.ListenUDP("udp4", tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			if w, ok := got.(*gatheringSocket); ok != tc.wrapped || (!ok && got != raw) {
				t.Fatalf("wrong socket type for %v: %T", tc.addr, got)
			} else if ok {
				if w.UDPConn != raw {
					t.Fatal("underlying socket replaced")
				}
				w.stop()
			}
		})
	}
	bindErr := errors.New("fixture bind failure")
	n.Net = fixtureBindNet{err: bindErr}
	if got, err := n.ListenUDP("udp4", nil); got != nil || !errors.Is(err, bindErr) {
		t.Fatalf("bind failure was hidden: %v / %v", got, err)
	}
}

func TestGatheringSocketBoundsServerListAndReturnsSnapshot(t *testing.T) {
	c := &gatheringSocket{started: true}
	ip := netip.MustParseAddr("192.0.2.1")
	for port := uint16(1); port <= maxTrackedSTUNServers+1; port++ {
		c.trackServer(netip.AddrPortFrom(ip, port))
	}
	known := netip.AddrPortFrom(ip, 1)
	c.trackServer(known)
	first := c.refreshTargets()
	if len(first) != maxTrackedSTUNServers || first[0] != known {
		t.Fatalf("unexpected retained server list: %v", first)
	}
	first[0] = netip.AddrPort{}
	c.confirmServer(netip.AddrPortFrom(ip, maxTrackedSTUNServers+1))
	if got := c.refreshTargets(); len(got) != maxTrackedSTUNServers || got[0] != known {
		t.Fatalf("untracked confirmation or snapshot mutation changed list: %v", got)
	}
	c.confirmServer(known)
	c.confirmServer(known)
	if got := c.refreshTargets(); len(got) != 1 || got[0] != known {
		t.Fatalf("confirmed server was not prioritized once: %v", got)
	}
	if got := normalizeAddrPort(netip.AddrPort{}); got.IsValid() {
		t.Fatalf("empty address became valid: %v", got)
	}
}

func TestGatheringRefreshUsesIPv6ConfirmationsForIPv6Targets(t *testing.T) {
	server := netip.MustParseAddrPort("[2001:db8::1]:3478")
	peer := netip.MustParseAddrPort("[2001:db8::2]:2345")
	ipv4 := netip.MustParseAddrPort("192.0.2.7:2345")
	base := &memoryUDP{writes: make(chan recordedDatagram, 16)}
	n := &signalingNet{ctx: t.Context(), interval: 10 * time.Millisecond}
	peers := []netip.AddrPort{ipv4, peer}
	n.remote.Store(&peers)
	c := &gatheringSocket{UDPConn: base, ctx: t.Context(), signaling: n, servers: []netip.AddrPort{server}, confirmed: []netip.AddrPort{server}}
	go c.refresh()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	kind := stun.NewType(stun.MethodBinding, stun.ClassIndication)
	for _, want := range []recordedDatagram{{server, kind}, {peer, kind}, {server, kind}} {
		select {
		case got := <-base.writes:
			if got != want {
				t.Fatalf("refresh target %+v, want %+v", got, want)
			}
		case <-timeout.C:
			t.Fatalf("no refresh for %+v", want)
		}
	}
}
