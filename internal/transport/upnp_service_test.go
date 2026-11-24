package transport

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fixtureGatewayRoundTripper func(*http.Request) (*http.Response, error)

func (f fixtureGatewayRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type fixtureGatewayBrokenBody struct{}

func (fixtureGatewayBrokenBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (fixtureGatewayBrokenBody) Close() error             { return nil }

func TestGatewayDescriptionFailuresDoNotReturnUsableService(t *testing.T) {
	const service = "<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>%s</controlURL></service></root>"
	for _, tc := range []struct {
		name, payload, want string
		status              int
		broken              bool
	}{
		{"router offline", "", "fixture router offline", 0, false},
		{"description gone", "", "HTTP 404", 404, false},
		{"interrupted body", "", "unreadable or too large", 200, true},
		{"oversized body", strings.Repeat(" ", upnpMaxResponseBytes+1), "unreadable or too large", 200, false},
		{"unrelated services", "<root><service><serviceType>urn:example:Printer</serviceType></service></root>", "no WANIPConnection", 200, false},
		{"unfinished document", "<root", "unexpected EOF", 200, false},
		{"invalid configuration", fmt.Sprintf(service, "/control/%"), "invalid URL escape", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: fixtureGatewayRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Path != "/desc.xml" {
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
				}
				if tc.status == 0 {
					return nil, errors.New("fixture router offline")
				}
				var body io.ReadCloser = io.NopCloser(strings.NewReader(tc.payload))
				if tc.broken {
					body = fixtureGatewayBrokenBody{}
				}
				return &http.Response{StatusCode: tc.status, Body: body}, nil
			})}
			got, err := fetchUPnPGateway(t.Context(), "http://192.168.100.1/desc.xml", client)
			if got != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("gateway = %v, error = %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestGatewayPortMappingLeaseBoundsAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lease   time.Duration
		seconds int
		reject  bool
	}{
		{"minimum lease", time.Second, 60, false},
		{"maximum lease", 48 * time.Hour, 86400, false},
		{"mapping unavailable", time.Minute, 60, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var actions []string
			gw := &upnpGateway{
				controlURL:  "http://192.168.100.1/control",
				serviceType: upnpServiceTypes[0],
				client: &http.Client{Transport: fixtureGatewayRoundTripper(func(r *http.Request) (*http.Response, error) {
					defer r.Body.Close()
					action := r.Header.Get("SOAPAction")
					actions = append(actions, action)
					status, reply := 200, "<Envelope/>"
					switch {
					case strings.HasSuffix(action, "#GetExternalIPAddress\""):
						reply = "<Envelope><NewExternalIPAddress>8.8.8.8</NewExternalIPAddress></Envelope>"
					case strings.HasSuffix(action, "#AddPortMapping\""):
						body, err := io.ReadAll(r.Body)
						if err != nil || !strings.Contains(string(body), fmt.Sprintf("<NewLeaseDuration>%d</NewLeaseDuration>", tc.seconds)) {
							t.Fatalf("lease not sent correctly: %s %v", body, err)
						}
						if tc.reject {
							status = 503
						}
					case strings.HasSuffix(action, "#DeletePortMapping\""):
					default:
						t.Fatalf("unexpected action %q", action)
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(reply))}, nil
				})},
			}
			pm, err := gw.addPortMapping(t.Context(), netip.MustParseAddrPort("192.168.100.10:51234"), tc.lease)
			if tc.reject {
				if pm != nil || err == nil || !strings.Contains(err.Error(), "HTTP 503") || len(actions) != 2 {
					t.Fatalf("failed mapping returned a lease: %v %v %v", pm, err, actions)
				}
				return
			}
			if err != nil || pm == nil || pm.external != netip.MustParseAddrPort("8.8.8.8:51234") {
				t.Fatalf("mapping = %v, error = %v", pm, err)
			}
			pm.Close()
			if len(actions) != 3 || !strings.HasSuffix(actions[2], "#DeletePortMapping\"") {
				t.Fatalf("successful lease not released: %v", actions)
			}
		})
	}
}

func TestGatewayExternalAddressErrorsStopBeforePortMapping(t *testing.T) {
	for _, tc := range []struct {
		name, payload, want string
		broken              bool
	}{
		{"read interrupted", "", "SOAP response invalid", true},
		{"response too large", strings.Repeat(" ", upnpMaxResponseBytes+1), "SOAP response invalid", false},
		{"missing address", "<Envelope/>", "missing XML element NewExternalIPAddress", false},
		{"malformed envelope", "<Envelope", "unexpected EOF", false},
		{"incomplete address", "<Envelope><NewExternalIPAddress>8.8.8.8", "unexpected EOF", false},
		{"invalid address", "<Envelope><NewExternalIPAddress>unknown</NewExternalIPAddress></Envelope>", "non-public external IP", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries := 0
			gw := &upnpGateway{
				controlURL:  "http://192.168.100.1/control",
				serviceType: upnpServiceTypes[0],
				client: &http.Client{Transport: fixtureGatewayRoundTripper(func(r *http.Request) (*http.Response, error) {
					defer r.Body.Close()
					queries++
					if r.Method != http.MethodPost || !strings.HasSuffix(r.Header.Get("SOAPAction"), "#GetExternalIPAddress\"") {
						t.Fatalf("unexpected request: %s %s", r.Method, r.Header.Get("SOAPAction"))
					}
					var body io.ReadCloser = io.NopCloser(strings.NewReader(tc.payload))
					if tc.broken {
						body = fixtureGatewayBrokenBody{}
					}
					return &http.Response{StatusCode: 200, Body: body}, nil
				})},
			}
			pm, err := gw.addPortMapping(t.Context(), netip.MustParseAddrPort("192.168.100.10:51234"), time.Hour)
			if pm != nil || err == nil || !strings.Contains(err.Error(), tc.want) || queries != 1 {
				t.Fatalf("mapping = %v, error = %v, queries = %d, want %q", pm, err, queries, tc.want)
			}
		})
	}
}

func TestGatewayMappingKeepsEligibleInterfaceAndAvoidsDuplicateCandidate(t *testing.T) {
	const header = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
	const ufrag = "a=ice-ufrag:fixture\r\n"
	const shared = "a=candidate:1 1 udp 100 192.168.200.30 41000 typ host\r\n" +
		"a=candidate:2 2 udp 100 192.168.100.10 41001 typ host\r\n" +
		"a=candidate:3 1 udp 100 2001:db8::10 41002 typ host\r\n" +
		"a=candidate:4 1 tcp 100 192.168.100.10 9 typ host tcptype active\r\n"
	const lanRoute = "a=candidate:5 1 udp 100 192.168.100.10 41003 typ host\r\n"
	const laterRoute = "a=candidate:6 1 udp 100 192.168.100.10 41004 typ host\r\n"
	const existing = "a=candidate:7 1 udp 100 8.8.8.8 41003 typ srflx raddr 192.168.100.10 rport 41003\r\n"

	for _, tc := range []struct {
		name, sdp        string
		externalStatus   int
		calls            int
		maps, equivalent bool
	}{
		{"no media", "v=0\r\n", 200, 0, false, true},
		{"empty media", header, 200, 0, false, true},
		{"other interfaces only", header + ufrag + shared, 200, 0, false, true},
		{"router temporarily unavailable", header + ufrag + lanRoute, 503, 1, false, true},
		{"already advertised", header + ufrag + shared + lanRoute + laterRoute + existing, 200, 2, true, true},
		{"new external candidate", header + ufrag + shared + lanRoute + laterRoute, 200, 2, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			lan := netip.MustParseAddr("192.168.100.10")
			gw := &upnpGateway{
				controlURL:  "http://192.168.100.1/control",
				serviceType: upnpServiceTypes[0],
				client: &http.Client{Transport: fixtureGatewayRoundTripper(func(r *http.Request) (*http.Response, error) {
					defer r.Body.Close()
					calls++
					action := r.Header.Get("SOAPAction")
					switch {
					case strings.HasSuffix(action, "#GetExternalIPAddress\""):
						return &http.Response{StatusCode: tc.externalStatus, Body: io.NopCloser(strings.NewReader("<NewExternalIPAddress>8.8.8.8</NewExternalIPAddress>"))}, nil
					case strings.HasSuffix(action, "#AddPortMapping\""):
						body, err := io.ReadAll(r.Body)
						if err != nil || !strings.Contains(string(body), "<NewInternalPort>41003</NewInternalPort>") ||
							!strings.Contains(string(body), "<NewInternalClient>"+lan.String()+"</NewInternalClient>") {
							t.Fatalf("wrong selected interface or socket: %s / %v", body, err)
						}
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<Envelope/>"))}, nil
					case strings.HasSuffix(action, "#DeletePortMapping\""):
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<Envelope/>"))}, nil
					default:
						t.Fatalf("unexpected gateway action %q", action)
						return nil, errors.New("unexpected action")
					}
				})},
			}
			updated, mapping := mapAndInjectUPnPForLAN(t.Context(), gw, lan, tc.sdp, time.Hour)
			if mapping != nil {
				t.Cleanup(mapping.Close)
			}
			if (mapping != nil) != tc.maps || calls != tc.calls || (updated == tc.sdp) != tc.equivalent {
				t.Fatalf("mapping %v, gateway calls %d, unchanged %t", mapping, calls, updated == tc.sdp)
			}
			if tc.maps && CountCandidates(updated).Mapped != 1 {
				t.Fatalf("expected precisely one advertised mapped candidate: %q", updated)
			}
		})
	}
}
