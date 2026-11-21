package transport

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"github.com/pion/webrtc/v4"
)

const (
	DefaultSTUN   = "stun:stun.cloudflare.com:3478,stun:stun.l.google.com:19302"
	gatherTimeout = 9 * time.Second
)

// STUNServers resolves the CLI policy into the destinations for this session.
// An empty string retains the original offline/LAN behavior for library callers.
func STUNServers(spec string) ([]string, error) {
	switch strings.TrimSpace(spec) {
	case "auto":
		spec = DefaultSTUN
	case "", "-", "none":
		return nil, nil
	}
	var urls []string
	seen := make(map[string]bool)
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		uri, err := stun.ParseURI(item)
		if err != nil || uri.Scheme != stun.SchemeTypeSTUN || uri.Port < 1 || uri.Port > 65535 || strings.ContainsAny(item, "/@?# \t\n\r") {
			return nil, errors.New("STUN 地址应为 stun:主机:端口，多个地址用英文逗号分隔")
		}
		url := uri.String()
		if !seen[url] {
			urls = append(urls, url)
			seen[url] = true
		}
	}
	return urls, nil
}

type Candidates struct {
	IPv4, IPv6, Mapped int
}

// CountCandidates summarizes the exact SDP being signed. Loopback is useful
// for same-machine tests but cannot provide a path to another device.
func CountCandidates(raw string) Candidates {
	var result Candidates
	desc := webrtc.SessionDescription{SDP: raw}
	sdp, err := desc.Unmarshal()
	if err != nil {
		return result
	}
	for _, media := range sdp.MediaDescriptions {
		for _, a := range media.Attributes {
			if a.Key != "candidate" {
				continue
			}
			c, err := ice.UnmarshalCandidate(a.Value)
			// Pion advertises the same socket for RTP and RTCP components.
			// The data transport uses component 1 only.
			if err != nil || c.Component() != 1 || !c.NetworkType().IsUDP() {
				continue
			}
			switch c.Type() {
			case ice.CandidateTypeServerReflexive:
				result.Mapped++
			case ice.CandidateTypeHost:
				ip, err := netip.ParseAddr(c.Address())
				if err == nil && !ip.IsLoopback() && !ip.IsUnspecified() {
					if ip.Unmap().Is4() {
						result.IPv4++
					} else {
						result.IPv6++
					}
				}
			}
		}
	}
	return result
}

func (c Candidates) String() string {
	return fmt.Sprintf("接口 IPv4 %d、IPv6 %d，STUN 映射 %d", c.IPv4, c.IPv6, c.Mapped)
}

// CheckNetwork uses the session's ICE configuration without an identity, a
// remote description or a connection to SSH.
func CheckNetwork(parent context.Context, spec string) (Candidates, error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	p, err := New(ctx, spec)
	if err != nil {
		return Candidates{}, err
	}
	defer p.Close()
	offer, err := p.Offer(ctx)
	if err != nil {
		return Candidates{}, err
	}
	return CountCandidates(offer), nil
}
