package transport

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5/stdnet"
)

func TestSTUNServerPolicy(t *testing.T) {
	for _, spec := range []string{"", "none", "-"} {
		if urls, err := STUNServers(spec); err != nil || len(urls) != 0 {
			t.Fatalf("%q enabled discovery: %v %v", spec, urls, err)
		}
	}
	urls, err := STUNServers("auto")
	if err != nil || len(urls) != 2 {
		t.Fatal("automatic discovery", urls, err)
	}
	urls, err = STUNServers(" stun:test.example,stun:test.example:3478, stun:[2001:db8::1]:19302 ")
	if err != nil || !slices.Equal(urls, []string{"stun:test.example:3478", "stun:[2001:db8::1]:19302"}) {
		t.Fatal("custom servers", urls, err)
	}
	for _, spec := range []string{"stun:test,", "stun:test:0", "stun:test:99999", "stun:test#fragment", "stun:test,turn:test"} {
		if _, err := STUNServers(spec); err == nil {
			t.Fatalf("accepted invalid server list %q", spec)
		}
	}
}

func TestOnlyDirectCandidates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for _, u := range []string{"turn:127.0.0.1:3478", "turns:example.org:5349", "https://example.org"} {
		if p, err := New(ctx, u); err == nil {
			p.Close()
			t.Fatalf("accepted %s", u)
		}
	}
	p, err := New(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	sdp, err := p.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := New(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	relayed := strings.ReplaceAll(sdp, " typ host", " typ relay")
	if _, err := other.Answer(ctx, relayed); err == nil {
		t.Fatal("accepted relay candidate")
	}
}

func TestSTUNPublishesMappedCandidate(t *testing.T) {
	t.Parallel()
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	dark, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dark.Close()
	var attempts atomic.Int32
	// Verify that the refresh really leaves Pion through the same source port
	// that produced the address signed into the offer.
	type packet struct {
		from string
		kind stun.MessageType
	}
	observed := make(chan packet, 16)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, sender, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			req := stun.Message{Raw: buf[:n]}
			if req.Decode() != nil {
				continue
			}
			observed <- packet{sender.String(), req.Type}
			if req.Type != stun.BindingRequest || attempts.Add(1) <= 2 {
				continue
			}
			mapping := &stun.XORMappedAddress{IP: net.IPv4(192, 0, 2, 17), Port: 40017}
			resp, err := stun.Build(stun.NewTransactionIDSetter(req.TransactionID), stun.BindingSuccess, mapping)
			if err == nil {
				_, _ = server.WriteTo(resp.Raw, sender)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	p, err := New(ctx, "stun:"+dark.LocalAddr().String()+",stun:"+server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	offer, err := p.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(offer, "192.0.2.17 40017 typ srflx") || CountCandidates(offer).Mapped != 1 {
		t.Fatal("the mapping returned by STUN is absent from the offer")
	}
	first := <-observed
	for {
		select {
		case got := <-observed:
			if got.from != first.from {
				t.Fatal("mapping changed sockets")
			}
			if got.kind == stun.NewType(stun.MethodBinding, stun.ClassIndication) {
				return
			}
		case <-ctx.Done():
			t.Fatal("no keepalive from the advertised mapping")
		}
	}
}

func TestRefreshUsesGatheringPortForRemoteFilter(t *testing.T) {
	t.Parallel()
	listen := func() *net.UDPConn {
		t.Helper()
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	server, remote := listen(), listen()
	network, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signaling := &signalingNet{Net: network, ctx: ctx, interval: 25 * time.Millisecond}
	conn, err := signaling.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := stun.MustBuild(stun.BindingRequest, stun.TransactionID)
	if _, err = conn.WriteTo(request.Raw, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	server.SetReadDeadline(time.Now().Add(time.Second))
	_, original, err := server.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	addr := remote.LocalAddr().(*net.UDPAddr).AddrPort()
	ports := []netip.AddrPort{netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())}
	signaling.remote.Store(&ports)
	remote.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := remote.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal("no refresh to the signaled endpoint", err)
	}
	msg := stun.Message{Raw: buf[:n]}
	if from != original || msg.Decode() != nil || msg.Type != stun.NewType(stun.MethodBinding, stun.ClassIndication) {
		t.Fatal("expected a Binding indication from the original gathering socket")
	}
	// Ending the exchange must stop refreshes even while the underlying ICE
	// socket remains open for the active SSH data channel.
	cancel()
	remote.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	for {
		before := time.Now()
		_, _, err = remote.ReadFromUDPAddrPort(buf)
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			break
		}
		if err != nil || time.Since(before) > 10*time.Millisecond {
			t.Fatalf("refresh continued after signaling ended: %v", err)
		}
	}
}
