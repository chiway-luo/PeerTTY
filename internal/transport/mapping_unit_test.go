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
