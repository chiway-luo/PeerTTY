// Package transport owns a single direct WebRTC connection and its ICE sockets.
package transport

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	piontransport "github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
	"github.com/pion/webrtc/v4"
)

const label = "peertty.ssh.v1"
const linkLabel = "peertty.ssh.link.v1"

// ErrDirectDisconnected indicates that an established direct peer was lost.
var ErrDirectDisconnected = errors.New("direct connection disconnected")

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
	roam        *roaming
	tryUPnP     bool
	mu          sync.Mutex
	closed      bool
	portMap     *portMapping
	tcpMux      ice.TCPMux
	startTCP    context.CancelFunc
}

type peerMode int

const (
	singleSession peerMode = iota
	reusableSession
	networkDiagnostic
)

func New(parent context.Context, spec string) (*Peer, error) {
	return newPeer(parent, spec, singleSession)
}

// A reusable grant can move its authenticated UDP path until the original
// authorization deadline. Older peers continue using ordinary ICE.
func NewGrant(parent context.Context, spec string) (*Peer, error) {
	return newPeer(parent, spec, reusableSession)
}

func newPeer(parent context.Context, spec string, mode peerMode) (*Peer, error) {
	urls, err := STUNServers(spec)
	if err != nil {
		return nil, err
	}
	var config webrtc.Configuration
	var settings webrtc.SettingEngine
	var signaling *signalingNet
	var roam *roaming
	lifetime, cancel := context.WithCancelCause(parent)
	refreshCtx, stopRefresh := context.WithCancel(parent)
	if len(urls) > 0 || mode == reusableSession {
		base, err := stdnet.NewNet()
		if err != nil {
			stopRefresh()
			cancel(err)
			return nil, err
		}
		var network piontransport.Net = base
		if mode == reusableSession {
			roam, err = newRoaming(lifetime)
			if err != nil {
				stopRefresh()
				cancel(err)
				return nil, err
			}
			network = &roamingNet{Net: network, roam: roam}
		}
		if len(urls) > 0 {
			signaling = &signalingNet{Net: network, ctx: refreshCtx, interval: 15 * time.Second}
			network = signaling
			config.ICEServers = []webrtc.ICEServer{{URLs: urls}}
		}
		settings.SetNet(network)
	}
	settings.SetSTUNGatherTimeout(gatherTimeout)
	settings.SetICEMaxBindingRequests(32)
	if mode == reusableSession {
		// The signed deadline bounds the checklist. A validated path can appear
		// even after the manual exchange or an initial extended outage.
		settings.SetICEMaxBindingRequests(math.MaxUint16)
		// Negotiate SCTP initialization in the signed SDP when both peers support
		// it. A handover between DTLS and the first terminal then has no separate
		// on-wire SCTP startup retry budget.
		settings.EnableSctpSnap(true)
		// Interactive streams can wait for a lone lost packet, with no later
		// packets to trigger fast retransmit. Bound exponential backoff
		// without changing reliability, ordering, or congestion control.
		settings.SetSCTPRTOMax(4 * time.Second)
	}
	settings.DetachDataChannels()
	settings.EnableDataChannelBlockWrite(true)
	settings.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6,
		webrtc.NetworkTypeTCP4, webrtc.NetworkTypeTCP6,
	})
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
	tcpMux, startTCP := newFallbackListener(lifetime)
	if tcpMux != nil {
		settings.SetICETCPMux(tcpMux)
	}
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(config)
	if err != nil {
		stopRefresh()
		cancel(err)
		startTCP()
		if tcpMux != nil {
			_ = tcpMux.Close()
		}
		return nil, err
	}
	p := &Peer{pc: pc, ready: make(chan opened, 1), lifetime: lifetime, cancel: cancel, stopRefresh: stopRefresh, signaling: signaling, roam: roam, tcpMux: tcpMux, startTCP: startTCP, tryUPnP: mode != networkDiagnostic && hasRemoteSTUN(urls)}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		reportConnectionState(mode, state, stopRefresh, cancel)
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) { _ = dc.Close() })
	return p, nil
}

func reportConnectionState(mode peerMode, state webrtc.PeerConnectionState, stopRefresh context.CancelFunc, cancel context.CancelCauseFunc) {
	if mode == reusableSession && state == webrtc.PeerConnectionStateDisconnected {
		return
	}
	switch state {
	case webrtc.PeerConnectionStateDisconnected:
		stopRefresh()
		cancel(ErrDirectDisconnected)
	case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
		stopRefresh()
		cancel(fmt.Errorf("direct connection %s", state))
	}
}

func (p *Peer) Context() context.Context { return p.lifetime }
func (p *Peer) Connected() bool          { return p.pc.ConnectionState() == webrtc.PeerConnectionStateConnected }

func (p *Peer) CanRoam() bool {
	if p.roam == nil || p.roam.keys.Load() == nil {
		return false
	}
	select {
	case <-p.roam.done:
		return false
	default:
		return true
	}
}

// BindGrant uses the signature of the exact approved answer, which also binds
// the offer digest, both device identities, SSH keys, scope and signed deadline.
func (p *Peer) BindGrant(receiptSignature []byte) error {
	if p.roam == nil {
		return nil
	}
	return p.roam.enable(receiptSignature, p.Connected)
}

func (p *Peer) Migrated() bool {
	if !p.CanRoam() {
		return false
	}
	p.roam.mu.Lock()
	defer p.roam.mu.Unlock()
	return p.roam.physical.socket != nil
}

func (p *Peer) Close() error {
	p.stopRefresh()
	p.cancel(context.Canceled)
	if p.roam != nil {
		p.roam.close()
	}
	p.mu.Lock()
	p.closed = true
	pm := p.portMap
	p.portMap = nil
	mux := p.tcpMux
	p.tcpMux = nil
	p.mu.Unlock()
	if pm != nil {
		pm.Close()
	}
	err := p.pc.Close()
	if mux != nil {
		err = errors.Join(err, mux.Close())
	}
	return err
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
		admitControlChannel(dc, &accepted, func() { p.attach(dc) })
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

// Incoming channels can be checked without a networked PeerConnection.
type incomingChannel interface {
	Label() string
	Ordered() bool
	MaxRetransmits() *uint16
	MaxPacketLifeTime() *uint16
	Close() error
	OnOpen(func())
	DetachWithDeadline() (datachannel.ReadWriteCloserDeadliner, error)
}

func admitControlChannel(dc incomingChannel, accepted *atomic.Bool, attach func()) {
	if dc.Label() != label || !dc.Ordered() || dc.MaxRetransmits() != nil ||
		dc.MaxPacketLifeTime() != nil || !accepted.CompareAndSwap(false, true) {
		_ = dc.Close()
		return
	}
	attach()
}

// Each SSH terminal gets a separate ordered SCTP stream on the same
// authenticated peer connection. Only the approving host enables this handler.
func (p *Peer) OnLink(handle func(datachannel.ReadWriteCloserDeadliner)) {
	p.pc.OnDataChannel(func(dc *webrtc.DataChannel) { admitTerminalChannel(dc, handle) })
}

func admitTerminalChannel(dc incomingChannel, handle func(datachannel.ReadWriteCloserDeadliner)) {
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
		var err error
		sdp, err = p.gatherMapping(ctx, gwCh, sdp, mapAndInjectUPnP)
		if err != nil {
			return "", err
		}
	}
	if p.roam != nil {
		sdp = p.roam.advertise(sdp)
	}
	return sdp, nil
}

// Discovery runs alongside ICE. Once it finishes, either retain the mapping as
// part of this peer's lifetime or close it if shutdown won the race.
func (p *Peer) gatherMapping(ctx context.Context, gateways <-chan *upnpGateway, sdp string, inject func(context.Context, *upnpGateway, string, time.Duration) (string, *portMapping)) (string, error) {
	var gw *upnpGateway
	select {
	case gw = <-gateways:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if gw == nil {
		return sdp, nil
	}
	lease := time.Hour
	if deadline, ok := p.lifetime.Deadline(); ok {
		if rem := time.Until(deadline); rem > 0 {
			lease = rem
		}
	}
	sdp, pm := inject(ctx, gw, sdp, lease)
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
	candidates, err := prepareRemoteICE(&desc)
	if err != nil {
		return err
	}
	if err := p.pc.SetRemoteDescription(desc); err != nil {
		return err
	}
	if p.signaling != nil {
		p.signaling.remote.Store(&candidates.mapped)
	}
	if p.roam != nil {
		p.roam.setRemote(candidates.roamKey, kind == webrtc.SDPTypeAnswer, candidates.contacts)
	}
	go p.enableTCPFallback(candidates)
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
		route, err := directRoute(pair, err)
		if err != nil {
			return nil, "", err
		}
		if pair.Local.Protocol == webrtc.ICEProtocolTCP && p.roam != nil {
			// The UDP path-recovery protocol cannot migrate a TCP stream.
			p.roam.close()
		}
		return result.channel, route, nil
	}
}

func directRoute(pair *webrtc.ICECandidatePair, err error) (string, error) {
	if err != nil || pair == nil {
		return "", errors.New("no selected ICE candidate pair")
	}
	if pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay {
		return "", errors.New("relayed path rejected")
	}
	return fmt.Sprintf("%s %s/%s", pair.Local.Protocol, pair.Local.Typ, pair.Remote.Typ), nil
}
