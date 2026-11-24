package transport

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/pion/webrtc/v4"
)

const fixtureSessionHeader = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
const fixtureDataMedia = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n"

func TestRemoteCandidatesKeepDistinctDirectUDPContactsInOfferOrder(t *testing.T) {
	var lines = []string{
		"a=mid:0",
		"a=" + roamAttribute + ":fixture-native-key",
		"a=candidate:1 1 udp 100 192.0.2.12 5000 typ host",
		"a=candidate:2 1 udp 100 192.0.2.12 5000 typ host",
		"a=candidate:3 1 udp 90 198.51.100.14 5001 typ srflx raddr 192.0.2.12 rport 5000",
		"a=candidate:4 1 udp 90 198.51.100.14 5001 typ srflx raddr 192.0.2.12 rport 5000",
		"a=candidate:5 1 udp 100 2001:db8::4 5002 typ host",
		"a=candidate:6 1 udp 100 127.0.0.1 5003 typ host",
		"a=candidate:7 2 udp 100 192.0.2.15 5004 typ host",
		"a=candidate:8 1 tcp 100 192.0.2.16 9 typ host tcptype active",
		"a=candidate:9 1 udp 100 machine.local 5006 typ host",
		"a=candidate:10 1 udp 100 fe80::15 5007 typ host",
	}
	sdp := fixtureSessionHeader + fixtureDataMedia + strings.Join(lines, "\r\n") + "\r\n"
	desc := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}
	candidates, err := prepareRemoteICE(&desc)
	wantMap := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.14:5001")}
	wantContacts := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.12:5000"), wantMap[0],
		netip.MustParseAddrPort("[2001:db8::4]:5002"), netip.MustParseAddrPort("127.0.0.1:5003")}
	if err != nil || candidates.roamKey != "fixture-native-key" || !slices.Equal(candidates.mapped, wantMap) || !slices.Equal(candidates.contacts, wantContacts) {
		t.Fatalf("remote candidates=%+v err=%v", candidates, err)
	}
	if len(candidates.tcp) != 1 || candidates.tcp[0].Candidate != strings.TrimPrefix(lines[9], "a=") || strings.Contains(desc.SDP, "tcptype active") {
		t.Fatalf("TCP candidates were not staged in wire order: %+v", candidates.tcp)
	}
}

func TestRemoteCandidatesNeedADataChannelAndPublishedCandidates(t *testing.T) {
	for _, tc := range []struct {
		name, sdp, want string
	}{
		{"no media description", fixtureSessionHeader, "single data-channel description"},
		{"voice description is not a data channel", fixtureSessionHeader + "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n", "single data-channel description"},
		{"data channel without gathered candidates", fixtureSessionHeader + fixtureDataMedia + "a=mid:0\r\n", "no direct ICE candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidates, err := prepareRemoteICE(&webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: tc.sdp})
			if err == nil || !strings.Contains(err.Error(), tc.want) || len(candidates.mapped)+len(candidates.contacts)+len(candidates.tcp) != 0 || candidates.roamKey != "" {
				t.Fatalf("remote candidates=%+v err=%v", candidates, err)
			}
		})
	}
}

func TestTCPComponentTwoCannotStartAnActiveDial(t *testing.T) {
	raw := fixtureSessionHeader + fixtureDataMedia +
		"a=candidate:1 1 udp 100 192.0.2.1 5001 typ host\r\n" +
		"a=candidate:2 2 tcp 100 192.0.2.1 5002 typ host tcptype passive\r\n" +
		"a=end-of-candidates\r\n"
	desc := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: raw}
	candidates, err := prepareRemoteICE(&desc)
	if err != nil || strings.Contains(desc.SDP, "tcptype") || len(candidates.tcp) != 1 || candidates.tcp[0].Candidate != "" {
		t.Fatalf("expected only a deferred end-of-candidates marker: %+v, %v", candidates.tcp, err)
	}
}
