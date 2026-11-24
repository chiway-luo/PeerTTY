package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

// Reserve the port before signing the ticket, but don't process passive TCP
// checks until this peer has had a chance to establish UDP. In particular,
// the controller may already be dialing while the host is reading the reply.
type fallbackListener struct {
	net.Listener
	ready context.Context
}

func (l fallbackListener) Accept() (net.Conn, error) {
	<-l.ready.Done()
	return l.Listener.Accept()
}

func newFallbackListener(lifetime context.Context) (ice.TCPMux, context.CancelFunc) {
	ready, start := context.WithCancel(lifetime)
	var config net.ListenConfig
	listener, err := config.Listen(lifetime, "tcp", ":0")
	if err != nil {
		return nil, start // Outbound ICE-TCP and UDP remain available.
	}
	return ice.NewTCPMuxDefault(ice.TCPMuxParams{
		Listener: fallbackListener{listener, ready}, ReadBufferSize: 8192, WriteBufferSize: 4 << 20,
		FirstStunBindTimeout: 5 * time.Second,
	}), start
}

type remoteICE struct {
	contacts, mapped []netip.AddrPort
	roamKey          string
	tcp              []webrtc.ICECandidateInit
}

// Inspect every candidate before applying any. Only the local copy passed to
// Pion is staged. The signature and pairing proof cover the original wire SDP.
func prepareRemoteICE(desc *webrtc.SessionDescription) (remoteICE, error) {
	parsed, err := desc.Unmarshal()
	if err != nil {
		return remoteICE{}, err
	}
	if len(parsed.MediaDescriptions) != 1 || parsed.MediaDescriptions[0].MediaName.Media != "application" {
		return remoteICE{}, errors.New("expected a single data-channel description")
	}
	var result remoteICE
	media := parsed.MediaDescriptions[0]
	initial := media.Attributes[:0]
	hasCandidate, hasTCP, ended := false, false, false
	for _, attr := range media.Attributes {
		switch attr.Key {
		case "candidate":
			c, err := ice.UnmarshalCandidate(attr.Value)
			if err != nil || c.Type() == ice.CandidateTypeRelay {
				return remoteICE{}, errors.New("invalid or relayed ICE candidate")
			}
			if c.Component() == 1 {
				hasCandidate = true
			}
			if c.NetworkType().IsTCP() {
				hasTCP = true
				if c.Component() == 1 {
					result.tcp = append(result.tcp, webrtc.ICECandidateInit{Candidate: "candidate:" + attr.Value})
				}
				continue
			}
			result.addUDPContact(c)
		case roamAttribute:
			result.roamKey = attr.Value
		case "end-of-candidates":
			ended = true
			continue
		}
		initial = append(initial, attr)
	}
	if !hasCandidate {
		return remoteICE{}, errors.New("peer has no direct ICE candidate")
	}
	if hasTCP {
		media.Attributes = initial
		raw, err := parsed.Marshal()
		if err != nil {
			return remoteICE{}, err
		}
		desc.SDP = string(raw)
		if ended {
			result.tcp = append(result.tcp, webrtc.ICECandidateInit{})
		}
	}
	return result, nil
}

func (r *remoteICE) addUDPContact(c ice.Candidate) {
	ip, err := netip.ParseAddr(c.Address())
	if err != nil || c.Component() != 1 || !(ip.IsGlobalUnicast() || ip.IsLoopback()) || c.Port() < 1 || c.Port() > 65535 {
		return
	}
	addr := netip.AddrPortFrom(ip.Unmap(), uint16(c.Port()))
	if !slices.Contains(r.contacts, addr) {
		r.contacts = append(r.contacts, addr)
	}
	if c.Type() == ice.CandidateTypeServerReflexive && ip.IsGlobalUnicast() && !slices.Contains(r.mapped, addr) {
		r.mapped = append(r.mapped, addr)
	}
}

func (p *Peer) enableTCPFallback(c remoteICE) {
	if len(c.contacts) > 0 {
		// Do not let early TCP handshakes compete with a healthy UDP path.
		// UDP checks continue after this window if neither path is ready yet.
		select {
		case <-p.lifetime.Done():
			return
		case <-time.After(2 * time.Second):
		}
		switch p.pc.ICEConnectionState() {
		case webrtc.ICEConnectionStateConnected, webrtc.ICEConnectionStateCompleted:
			return
		}
	}
	if p.lifetime.Err() != nil {
		return
	}
	p.startTCP()
	for _, candidate := range c.tcp {
		if err := p.pc.AddICECandidate(candidate); err != nil {
			p.cancel(fmt.Errorf("apply signed ICE-TCP candidate: %w", err))
			return
		}
	}
}
