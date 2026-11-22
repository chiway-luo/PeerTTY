package transport

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5"
)

const maxTrackedSTUNServers = 16

// During manual signaling a gateway can expire the mapping advertised in
// the signed ticket. Refresh it from the gathering socket to its original
// STUN server. Port-restricted gateways also expire a separate entry for each
// peer destination. Refresh only the mapped endpoints in the signed SDP.
// Pion takes over consent/keepalive on the selected peer path.
type signalingNet struct {
	transport.Net
	ctx      context.Context
	interval time.Duration
	remote   atomic.Pointer[[]netip.AddrPort]
}

func (n *signalingNet) ListenUDP(network string, addr *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := n.Net.ListenUDP(network, addr)
	if err != nil || (addr != nil && len(addr.IP) > 0 && !addr.IP.IsUnspecified()) {
		return conn, err
	}
	ctx, cancel := context.WithCancel(n.ctx)
	return &gatheringSocket{UDPConn: conn, ctx: ctx, stop: cancel, signaling: n}, nil
}

type gatheringSocket struct {
	transport.UDPConn
	ctx       context.Context
	stop      context.CancelFunc
	mu        sync.Mutex
	servers   []netip.AddrPort
	confirmed []netip.AddrPort
	started   bool
	signaling *signalingNet
}

func (c *gatheringSocket) WriteTo(b []byte, dst net.Addr) (int, error) {
	n, err := c.UDPConn.WriteTo(b, dst)
	if err == nil && isDiscoveryBindingRequest(b) {
		if udp, ok := dst.(*net.UDPAddr); ok {
			ap := normalizeAddrPort(udp.AddrPort())
			if ap.IsValid() {
				c.trackServer(ap)
			}
		}
	}
	return n, err
}

func (c *gatheringSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, src, err := c.UDPConn.ReadFrom(b)
	if err == nil && n > 0 && isBindingSuccess(b[:n]) {
		if udp, ok := src.(*net.UDPAddr); ok {
			ap := normalizeAddrPort(udp.AddrPort())
			if ap.IsValid() {
				c.confirmServer(ap)
			}
		}
	}
	return n, src, err
}

func isDiscoveryBindingRequest(b []byte) bool {
	if !stun.IsMessage(b) {
		return false
	}
	// Pion begins server-reflexive discovery with an unauthenticated
	// Binding request. ICE checks to a peer carry USERNAME and integrity.
	request := stun.Message{Raw: b}
	return request.Decode() == nil && request.Type == stun.BindingRequest && len(request.Attributes) == 0
}

func isBindingSuccess(b []byte) bool {
	if !stun.IsMessage(b) {
		return false
	}
	msg := stun.Message{Raw: b}
	return msg.Decode() == nil && msg.Type == stun.BindingSuccess
}

func normalizeAddrPort(ap netip.AddrPort) netip.AddrPort {
	if !ap.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (c *gatheringSocket) trackServer(ap netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Contains(c.servers, ap) && len(c.servers) < maxTrackedSTUNServers {
		c.servers = append(c.servers, ap)
	}
	if !c.started {
		c.started = true
		go c.refresh()
	}
}

func (c *gatheringSocket) confirmServer(ap netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if slices.Contains(c.servers, ap) && !slices.Contains(c.confirmed, ap) {
		c.confirmed = append(c.confirmed, ap)
	}
}

func (c *gatheringSocket) refreshTargets() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	src := c.servers
	if len(c.confirmed) > 0 {
		src = c.confirmed
	}
	out := make([]netip.AddrPort, len(src))
	copy(out, src)
	return out
}

func (c *gatheringSocket) refresh() {
	ticker := time.NewTicker(c.signaling.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		if c.ctx.Err() != nil {
			return
		}
		targets := c.refreshTargets()
		if len(targets) == 0 {
			continue
		}
		msg, err := stun.Build(stun.NewType(stun.MethodBinding, stun.ClassIndication), stun.TransactionID)
		if err != nil {
			continue
		}
		var hasV4, hasV6 bool
		for _, srv := range targets {
			if c.ctx.Err() != nil {
				return
			}
			if srv.Addr().Is4() {
				hasV4 = true
			} else {
				hasV6 = true
			}
			_, _ = c.UDPConn.WriteTo(msg.Raw, net.UDPAddrFromAddrPort(srv))
		}
		peers := c.signaling.remote.Load()
		if peers == nil {
			continue
		}
		for _, peer := range *peers {
			if c.ctx.Err() != nil {
				return
			}
			if (peer.Addr().Is4() && hasV4) || (!peer.Addr().Is4() && hasV6) {
				_, _ = c.UDPConn.WriteTo(msg.Raw, net.UDPAddrFromAddrPort(peer))
			}
		}
	}
}

func (c *gatheringSocket) Close() error {
	c.stop()
	return c.UDPConn.Close()
}
