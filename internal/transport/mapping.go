package transport

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5"
)

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
	first     sync.Once
	signaling *signalingNet
}

func (c *gatheringSocket) WriteTo(b []byte, dst net.Addr) (int, error) {
	n, err := c.UDPConn.WriteTo(b, dst)
	if err == nil {
		c.first.Do(func() {
			// Pion begins server-reflexive discovery with an unauthenticated
			// Binding request. ICE checks to a peer carry a USERNAME and integrity.
			request := stun.Message{Raw: b}
			if stun.IsMessage(b) && request.Decode() == nil && request.Type == stun.BindingRequest && len(request.Attributes) == 0 {
				go c.refresh(dst)
			}
		})
	}
	return n, err
}

func (c *gatheringSocket) refresh(server net.Addr) {
	serverIP, ok := server.(*net.UDPAddr)
	if !ok {
		return
	}
	isIPv4 := serverIP.AddrPort().Addr().Unmap().Is4()
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
		msg, err := stun.Build(stun.NewType(stun.MethodBinding, stun.ClassIndication), stun.TransactionID)
		if err != nil {
			continue
		}
		_, _ = c.UDPConn.WriteTo(msg.Raw, server)
		peers := c.signaling.remote.Load()
		if peers == nil {
			continue
		}
		for _, peer := range *peers {
			if peer.Addr().Is4() == isIPv4 && c.ctx.Err() == nil {
				_, _ = c.UDPConn.WriteTo(msg.Raw, net.UDPAddrFromAddrPort(peer))
			}
		}
	}
}

func (c *gatheringSocket) Close() error {
	c.stop()
	return c.UDPConn.Close()
}
