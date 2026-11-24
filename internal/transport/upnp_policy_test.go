package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureSSDPSocket struct {
	mu          sync.Mutex
	closed      bool
	searches    []string
	destination []string
	deadline    time.Time
	reply       string
}

func (s *fixtureSSDPSocket) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reply == "" {
		return 0, nil, io.EOF
	}
	n := copy(buf, s.reply)
	s.reply = ""
	return n, nil, nil
}
func (s *fixtureSSDPSocket) WriteToUDP(data []byte, to *net.UDPAddr) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.searches = append(s.searches, string(data))
	s.destination = append(s.destination, to.String())
	return len(data), nil
}
func (s *fixtureSSDPSocket) SetReadDeadline(deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = deadline
	return nil
}
func (s *fixtureSSDPSocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func TestUPnPDiscoveryUsesBoundedLocalSearchAndClosesSocket(t *testing.T) {
	const location = "http://192.168.16.1/igd.xml"
	for _, available := range []bool{true, false} {
		t.Run(fmt.Sprintf("available=%t", available), func(t *testing.T) {
			s := &fixtureSSDPSocket{reply: "Location: " + location + "\r\n"}
			gateway := &upnpGateway{gatewayHost: netip.MustParseAddr("192.168.16.1")}
			fetches := 0
			got := discoverUPnPGatewayWith(t.Context(), func() (ssdpSocket, error) {
				if !available {
					return nil, errors.New("fixture discovery socket unavailable")
				}
				return s, nil
			}, func(ctx context.Context, url string, _ *http.Client) (*upnpGateway, error) {
				fetches++
				deadline, ok := ctx.Deadline()
				s.mu.Lock()
				socketDeadline := s.deadline
				s.mu.Unlock()
				if url != location || !ok || !deadline.Equal(socketDeadline) || time.Until(deadline) > upnpDiscoveryTimeout {
					t.Fatalf("wrong discovery request: %q, %v / %v", url, deadline, socketDeadline)
				}
				return gateway, nil
			})
			s.mu.Lock()
			defer s.mu.Unlock()
			if !available {
				if got != nil || fetches != 0 || len(s.searches) != 0 {
					t.Fatalf("unavailable socket still searched: %v, %d, %q", got, fetches, s.searches)
				}
				return
			}
			if got != gateway || fetches != 1 || !s.closed ||
				!slices.Equal(s.destination, []string{"239.255.255.250:1900", "239.255.255.250:1900"}) || len(s.searches) != 2 {
				t.Fatalf("discovery=%v requests=%v fetches=%d closed=%t", got, s.destination, fetches, s.closed)
			}
			for i, version := range []string{"2", "1"} {
				if !strings.HasPrefix(s.searches[i], "M-SEARCH * HTTP/1.1\r\n") ||
					!strings.Contains(s.searches[i], "InternetGatewayDevice:"+version+"\r\n") {
					t.Fatalf("unexpected discovery request: %q", s.searches[i])
				}
			}
		})
	}
}

func TestUPnPExternalIPv4Classification(t *testing.T) {
	for _, tt := range []struct {
		addr   string
		public bool
	}{
		{"2001:db8::1", false},
		{"127.0.0.1", false},
		{"192.168.10.2", false},
		{"100.64.0.7", false},
		{"198.51.100.7", false},
		{"192.0.0.8", false},
		{"192.0.0.9", true},
		{"192.0.0.10", true},
		{"8.8.8.8", true},
	} {
		if got := publicIPv4(netip.MustParseAddr(tt.addr)); got != tt.public {
			t.Errorf("publicIPv4(%q) = %v, want %v", tt.addr, got, tt.public)
		}
	}
}

func TestUPnPDescriptionRejectsUnsupportedEndpointKinds(t *testing.T) {
	const service = "<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>%s</controlURL></service>"
	for _, controlURL := range []string{"https://192.168.16.1/ctl", "http://router.local/ctl"} {
		t.Run(controlURL, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: fixtureGatewayRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodGet || req.URL.Path != "/igd.xml" {
					t.Fatal("unexpected control request")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(service, controlURL)))}, nil
			})}
			got, err := fetchUPnPGateway(t.Context(), "http://192.168.16.1/igd.xml", client)
			if got != nil || err == nil || !strings.Contains(err.Error(), "escapes gateway host") || calls != 1 {
				t.Fatalf("gateway=%v err=%v calls=%d", got, err, calls)
			}
		})
	}
	for _, loc := range []string{"http://", "http://192.168.16.1/%"} {
		if _, _, err := validateLANURL(loc, false); err == nil {
			t.Errorf("accepted unavailable router address %q", loc)
		}
	}
}

func TestUPnPIneligibleCandidatesDoNotOpenMapping(t *testing.T) {
	lan := netip.MustParseAddr("192.168.16.2")
	gw := &upnpGateway{client: &http.Client{Transport: fixtureGatewayRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("no candidate qualified for a router mapping")
		return nil, errors.New("unexpected request")
	})}}
	for _, sdp := range []string{
		"not an SDP",
		fixtureSessionHeader + fixtureDataMedia + "a=candidate:1 1 udp 100 machine.local 40100 typ host\r\n",
		fixtureSessionHeader + fixtureDataMedia + "a=candidate:1 1 udp 100 192.168.16.2 0 typ host\r\n",
		fixtureSessionHeader + fixtureDataMedia + "a=candidate:1 1 udp 100 192.168.16.2 40100 typ prflx raddr 192.168.16.2 rport 40101\r\n",
	} {
		if got, mapping := mapAndInjectUPnPForLAN(t.Context(), gw, lan, sdp, time.Minute); got != sdp || mapping != nil {
			t.Fatalf("ineligible route modified description: %q / %v", got, mapping)
		}
	}
}
