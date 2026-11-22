// Package transport owns a single direct WebRTC connection and its ICE sockets.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5/stdnet"
	"github.com/pion/webrtc/v4"
)

const label = "peertty.ssh.v1"
const linkLabel = "peertty.ssh.link.v1"

type opened struct {
	channel datachannel.ReadWriteCloserDeadliner
	err     error
}

type Peer struct {
	pc          *webrtc.PeerConnection
	ready       chan opened
	lifetime    context.Context
	cancel      context.CancelCauseFunc
	stopRefresh context.CancelFunc
	signaling   *signalingNet
	tryUPnP     bool
	mu          sync.Mutex
	closed      bool
	portMap     *portMapping
}

func New(parent context.Context, spec string) (*Peer, error) {
	return newPeer(parent, spec, false)
}

// A reusable grant lets ICE recover its existing route after a transient
// disconnection. The caller still owns the original authorization deadline.
func NewGrant(parent context.Context, spec string) (*Peer, error) { return newPeer(parent, spec, true) }

func newPeer(parent context.Context, spec string, reusable bool) (*Peer, error) {
	urls, err := STUNServers(spec)
	if err != nil {
		return nil, err
	}
	var config webrtc.Configuration
	var settings webrtc.SettingEngine
	var signaling *signalingNet
	refreshCtx, stopRefresh := context.WithCancel(parent)
	if len(urls) > 0 {
		network, err := stdnet.NewNet()
		if err != nil {
			stopRefresh()
			return nil, err
		}
		signaling = &signalingNet{Net: network, ctx: refreshCtx, interval: 15 * time.Second}
		settings.SetNet(signaling)
		config.ICEServers = []webrtc.ICEServer{{URLs: urls}}
	}
	settings.SetSTUNGatherTimeout(gatherTimeout)
	settings.SetICEMaxBindingRequests(32)
	settings.DetachDataChannels()
	settings.EnableDataChannelBlockWrite(true)
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	// Loopback only reaches a peer on the same machine. Keep it for offline
	// and same-host checks, and omit it from tickets that cross a network.
	settings.SetIncludeLoopbackCandidate(len(urls) == 0)
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	exchangeWindow := 25 * time.Second
	if deadline, ok := parent.Deadline(); ok {
		exchangeWindow = max(exchangeWindow, time.Until(deadline))
	}
	// The failure window also covers manual signaling. Report loss on an
	// established route separately, after three missed keepalive intervals.
	settings.SetICETimeouts(6*time.Second, exchangeWindow, 2*time.Second)
	settings.SetSCTPMaxMessageSize(16 * 1024)
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(config)
	if err != nil {
		stopRefresh()
		return nil, err
	}
	lifetime, cancel := context.WithCancelCause(parent)
	p := &Peer{pc: pc, ready: make(chan opened, 1), lifetime: lifetime, cancel: cancel, stopRefresh: stopRefresh, signaling: signaling, tryUPnP: hasRemoteSTUN(urls)}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if reusable && state == webrtc.PeerConnectionStateDisconnected {
			return
		}
		switch state {
		case webrtc.PeerConnectionStateDisconnected, webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			stopRefresh()
			cancel(fmt.Errorf("direct connection %s", state))
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) { _ = dc.Close() })
	return p, nil
}

func (p *Peer) Context() context.Context { return p.lifetime }
func (p *Peer) Connected() bool          { return p.pc.ConnectionState() == webrtc.PeerConnectionStateConnected }

func (p *Peer) Close() error {
	p.stopRefresh()
	p.cancel(context.Canceled)
	p.mu.Lock()
	p.closed = true
	pm := p.portMap
	p.portMap = nil
	p.mu.Unlock()
	if pm != nil {
		pm.Close()
	}
	return p.pc.Close()
}

func (p *Peer) attach(dc *webrtc.DataChannel) {
	dc.OnOpen(func() {
		stream, err := dc.DetachWithDeadline()
		p.ready <- opened{channel: stream, err: err}
	})
}

func (p *Peer) Offer(ctx context.Context) (string, error) {
	dc, err := p.pc.CreateDataChannel(label, nil)
	if err != nil {
		return "", err
	}
	p.attach(dc)
	desc, err := p.pc.CreateOffer(nil)
	if err != nil {
		return "", err
	}
	return p.gather(ctx, desc)
}

func (p *Peer) Answer(ctx context.Context, offer string) (string, error) {
	var accepted atomic.Bool
	p.pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() != label || !dc.Ordered() || dc.MaxRetransmits() != nil ||
			dc.MaxPacketLifeTime() != nil || !accepted.CompareAndSwap(false, true) {
			_ = dc.Close()
			return
		}
		p.attach(dc)
	})
	if err := p.setRemote(webrtc.SDPTypeOffer, offer); err != nil {
		return "", err
	}
	desc, err := p.pc.CreateAnswer(nil)
	if err != nil {
		return "", err
	}
	return p.gather(ctx, desc)
}

func (p *Peer) Accept(answer string) error { return p.setRemote(webrtc.SDPTypeAnswer, answer) }

// Each SSH terminal gets a separate ordered SCTP stream on the same
// authenticated peer connection. Only the approving host enables this handler.
func (p *Peer) OnLink(handle func(datachannel.ReadWriteCloserDeadliner)) {
	p.pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() != linkLabel || !dc.Ordered() || dc.MaxRetransmits() != nil || dc.MaxPacketLifeTime() != nil {
			_ = dc.Close()
			return
		}
		dc.OnOpen(func() {
			stream, err := dc.DetachWithDeadline()
			if err == nil {
				handle(stream)
			} else {
				_ = dc.Close()
			}
		})
	})
}

func (p *Peer) OpenLink(ctx context.Context) (datachannel.ReadWriteCloserDeadliner, error) {
	dc, err := p.pc.CreateDataChannel(linkLabel, nil)
	if err != nil {
		return nil, err
	}
	ready := make(chan opened, 1)
	dc.OnOpen(func() { stream, err := dc.DetachWithDeadline(); ready <- opened{stream, err} })
	select {
	case result := <-ready:
		return result.channel, result.err
	case <-ctx.Done():
		_ = dc.Close()
		return nil, ctx.Err()
	case <-p.lifetime.Done():
		_ = dc.Close()
		return nil, context.Cause(p.lifetime)
	}
}

func hasRemoteSTUN(urls []string) bool {
	for _, raw := range urls {
		uri, err := stun.ParseURI(raw)
		if err != nil {
			continue
		}
		if ip, err := netip.ParseAddr(uri.Host); err == nil {
			if !ip.IsLoopback() {
				return true
			}
			continue
		}
		if !strings.EqualFold(uri.Host, "localhost") {
			return true
		}
	}
	return false
}

func (p *Peer) gather(ctx context.Context, desc webrtc.SessionDescription) (string, error) {
	var gwCh chan *upnpGateway
	if p.tryUPnP {
		gwCh = make(chan *upnpGateway, 1)
		go func() { gwCh <- discoverUPnPGateway(ctx) }()
	}
	done := webrtc.GatheringCompletePromise(p.pc)
	if err := p.pc.SetLocalDescription(desc); err != nil {
		return "", err
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-done:
	}
	sdp := compactSDP(p.pc.LocalDescription().SDP)
	if gwCh != nil {
		var gw *upnpGateway
		select {
		case gw = <-gwCh:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		if gw != nil {
			lease := time.Hour
			if deadline, ok := p.lifetime.Deadline(); ok {
				if rem := time.Until(deadline); rem > 0 {
					lease = rem
				}
			}
			var pm *portMapping
			sdp, pm = mapAndInjectUPnP(ctx, gw, sdp, lease)
			if pm != nil {
				p.mu.Lock()
				if p.closed {
					p.mu.Unlock()
					pm.Close()
				} else {
					p.portMap = pm
					p.mu.Unlock()
				}
			}
		}
	}
	return sdp, nil
}

// Pion repeats every candidate as component 2 (RTCP). A data channel uses
// component 1 only, so the copies would just double the signed ticket.
func compactSDP(raw string) string {
	lines := strings.SplitAfter(raw, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if value, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), "a=candidate:"); ok {
			if c, err := ice.UnmarshalCandidate(value); err == nil && c.Component() != 1 {
				continue
			}
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "")
}

func (p *Peer) setRemote(kind webrtc.SDPType, raw string) error {
	desc := webrtc.SessionDescription{Type: kind, SDP: raw}
	parsed, err := desc.Unmarshal()
	if err != nil {
		return err
	}
	if len(parsed.MediaDescriptions) != 1 || parsed.MediaDescriptions[0].MediaName.Media != "application" {
		return errors.New("expected a single data-channel description")
	}
	count := 0
	var mapped []netip.AddrPort
	for _, attr := range parsed.MediaDescriptions[0].Attributes {
		if attr.Key == "candidate" {
			candidate, err := ice.UnmarshalCandidate(attr.Value)
			if err != nil || candidate.Type() == ice.CandidateTypeRelay {
				return errors.New("invalid or relayed ICE candidate")
			}
			if candidate.Type() == ice.CandidateTypeServerReflexive && candidate.Component() == 1 && candidate.NetworkType().IsUDP() {
				ip, err := netip.ParseAddr(candidate.Address())
				if err == nil && ip.IsGlobalUnicast() && candidate.Port() > 0 && candidate.Port() <= 65535 {
					addr := netip.AddrPortFrom(ip.Unmap(), uint16(candidate.Port()))
					if !slices.Contains(mapped, addr) {
						mapped = append(mapped, addr)
					}
				}
			}
			count++
		}
	}
	if count == 0 {
		return errors.New("peer has no direct ICE candidate")
	}
	if err := p.pc.SetRemoteDescription(desc); err != nil {
		return err
	}
	if p.signaling != nil {
		p.signaling.remote.Store(&mapped)
	}
	return nil
}

func (p *Peer) Channel(ctx context.Context) (datachannel.ReadWriteCloserDeadliner, string, error) {
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-p.lifetime.Done():
		return nil, "", context.Cause(p.lifetime)
	case result := <-p.ready:
		p.stopRefresh()
		if result.err != nil {
			return nil, "", result.err
		}
		pair, err := p.pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
		if err != nil || pair == nil {
			return nil, "", errors.New("no selected ICE candidate pair")
		}
		if pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay {
			return nil, "", errors.New("relayed path rejected")
		}
		route := fmt.Sprintf("%s %s/%s", pair.Local.Protocol, pair.Local.Typ, pair.Remote.Typ)
		return result.channel, route, nil
	}
}
