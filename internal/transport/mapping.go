package transport

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5"
)

const (
	maxTrackedSTUNServers = 16
	maxDiscoveryRetries   = 6
)

// During manual signaling a gateway can expire the mapping advertised in
// the signed ticket. Refresh it from the gathering socket to its original
// STUN server. Port-restricted gateways also expire a separate entry for each
// peer destination. Refresh only the mapped endpoints in the signed SDP.
// Pion takes over consent/keepalive on the selected peer path.
type signalingNet struct {
	transport.Net
	ctx        context.Context
	interval   time.Duration
	retryDelay time.Duration
	remote     atomic.Pointer[[]netip.AddrPort]
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
	requests  map[netip.AddrPort]discoveryRequest
	started   bool
	retrying  bool
	signaling *signalingNet
}

type discoveryRequest struct {
	id          [stun.TransactionIDSize]byte
	raw         []byte
	retriesLeft int
}

func (c *gatheringSocket) WriteTo(b []byte, dst net.Addr) (int, error) {
	udp, ok := dst.(*net.UDPAddr)
	if !ok || !udp.AddrPort().IsValid() {
		return c.UDPConn.WriteTo(b, dst)
	}
	request := bindingMessage(b, stun.BindingRequest)
	// Authenticated ICE checks to peers carry USERNAME and integrity.
	if request == nil || len(request.Attributes) != 0 {
		return c.UDPConn.WriteTo(b, dst)
	}
	// A loopback server can respond before WriteTo returns. Make a successful
	// discovery write and its registration atomic with respect to ReadFrom.
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.UDPConn.WriteTo(b, dst)
	if err == nil && n == len(b) {
		c.recordDiscoveryLocked(normalizeAddrPort(udp.AddrPort()), request)
	}
	return n, err
}

func (c *gatheringSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, src, err := c.UDPConn.ReadFrom(b)
	if udp, ok := src.(*net.UDPAddr); err == nil && n > 0 && ok {
		response := bindingMessage(b[:n], stun.BindingSuccess)
		if response != nil && hasMappedAddress(response) {
			c.confirmServer(normalizeAddrPort(udp.AddrPort()), response.TransactionID)
		}
	}
	return n, src, err
}

func bindingMessage(raw []byte, kind stun.MessageType) *stun.Message {
	if !stun.IsMessage(raw) {
		return nil
	}
	msg := &stun.Message{Raw: raw}
	if msg.Decode() != nil || msg.Type != kind {
		return nil
	}
	return msg
}

// Accept the same two address attributes as Pion's STUN gatherer.
func hasMappedAddress(msg *stun.Message) bool {
	var addr stun.XORMappedAddress
	err := addr.GetFrom(msg)
	if errors.Is(err, stun.ErrAttributeNotFound) {
		var legacy stun.MappedAddress
		err = legacy.GetFrom(msg)
		addr.IP, addr.Port = legacy.IP, legacy.Port
	}
	return err == nil && addr.Port > 0 && addr.IP.To16() != nil && !addr.IP.IsUnspecified()
}

func normalizeAddrPort(ap netip.AddrPort) netip.AddrPort {
	if !ap.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Keep the latest transaction ID even after its retry budget is exhausted:
// a delayed matching response can still confirm the mapping.
func (c *gatheringSocket) recordDiscoveryLocked(ap netip.AddrPort, msg *stun.Message) {
	previous, known := c.requests[ap]
	if known && previous.id == msg.TransactionID {
		return
	}
	if !known {
		if len(c.servers) >= maxTrackedSTUNServers {
			return
		}
		c.servers = append(c.servers, ap)
	}
	if c.requests == nil {
		c.requests = make(map[netip.AddrPort]discoveryRequest)
	}
	req := discoveryRequest{id: msg.TransactionID}
	if c.signaling != nil && c.signaling.retryDelay > 0 {
		req.raw = bytes.Clone(msg.Raw)
		req.retriesLeft = maxDiscoveryRetries
		if !c.retrying {
			c.retrying = true
			go c.retryDiscovery()
		}
	}
	c.requests[ap] = req
	if !c.started {
		c.started = true
		go c.refresh()
	}
}

func (c *gatheringSocket) confirmServer(ap netip.AddrPort, id [stun.TransactionIDSize]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	req, ok := c.requests[ap]
	if !ok || req.id != id {
		return
	}
	if !slices.Contains(c.confirmed, ap) {
		c.confirmed = append(c.confirmed, ap)
	}
	c.requests[ap] = discoveryRequest{id: id}
}

type pendingDiscoveryItem struct {
	server netip.AddrPort
	raw    []byte
}

func (c *gatheringSocket) pendingDiscovery() []pendingDiscoveryItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []pendingDiscoveryItem
	for _, srv := range c.servers {
		req := c.requests[srv]
		if req.retriesLeft == 0 {
			continue
		}
		out = append(out, pendingDiscoveryItem{server: srv, raw: req.raw})
		req.retriesLeft--
		if req.retriesLeft == 0 {
			req.raw = nil
		}
		c.requests[srv] = req
	}
	if len(out) == 0 {
		c.retrying = false
	}
	return out
}

func (c *gatheringSocket) retryDiscovery() {
	ticker := time.NewTicker(c.signaling.retryDelay)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		items := c.pendingDiscovery()
		if len(items) == 0 {
			return
		}
		for _, item := range items {
			if c.ctx.Err() != nil {
				return
			}
			_, _ = c.UDPConn.WriteTo(item.raw, net.UDPAddrFromAddrPort(item.server))
		}
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
