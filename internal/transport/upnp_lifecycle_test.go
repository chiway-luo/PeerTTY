package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestUPnPDefaultDescriptionClientHonorsCanceledRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// Policy allows loopback here only to exercise the default client with an
	// already canceled context. No router, port mapping or network dependency.
	gw, err := fetchUPnPGatewayWithPolicy(ctx, "http://127.0.0.1:1/fixture.xml", nil, true)
	if gw != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled description fetch returned %v, %v", gw, err)
	}
}

func TestUPnPControlRequestReportsSetupAndTransportFailures(t *testing.T) {
	offline := errors.New("fixture router stopped")
	for _, tc := range []struct {
		name, url string
		ctx       context.Context
		calls     int
		want      error
	}{
		{"cannot construct request", "http://192.168.100.1/%", t.Context(), 0, nil},
		{"cannot send request", "http://192.168.100.1/control", t.Context(), 1, offline},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			g := &upnpGateway{controlURL: tc.url, serviceType: upnpServiceTypes[0], client: &http.Client{
				Transport: fixtureGatewayRoundTripper(func(req *http.Request) (*http.Response, error) {
					calls++
					_ = req.Body.Close()
					return nil, offline
				}),
			}}
			err := g.deletePortMapping(tc.ctx, 42000)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || calls != tc.calls {
				t.Fatalf("cleanup result %v after %d requests", err, calls)
			}
		})
	}
	var neverAllocated *portMapping
	neverAllocated.Close()
	(&portMapping{}).Close()
}

func TestUPnPServicesPreferSupportedVersionAndIgnoreIncompleteEntry(t *testing.T) {
	xml := `<root>
	  <service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>/ppp</controlURL></service>
	  <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><controlURL> </controlURL></service>
	  <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL> /one </controlURL></service>
	</root>`
	typ, path, err := parseUPnPServices([]byte(xml))
	if typ != upnpServiceTypes[1] || path != "/one" || err != nil {
		t.Fatalf("description did not select best usable service: %s / %q / %v", typ, path, err)
	}
}

func TestUPnPOnlyUsesIPv4RouteFacingGatewayAndKeepsOriginalOnFailure(t *testing.T) {
	const raw = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"a=candidate:1 1 udp 100 127.0.0.1 42000 typ host\r\n"
	for _, address := range []string{"::1", "127.0.0.1"} {
		t.Run(address, func(t *testing.T) {
			ip := netip.MustParseAddr(address)
			calls := 0
			gw := &upnpGateway{
				gatewayHost: ip,
				controlURL:  "http://127.0.0.1/control",
				serviceType: upnpServiceTypes[0],
				client: &http.Client{Transport: fixtureGatewayRoundTripper(func(req *http.Request) (*http.Response, error) {
					calls++
					_ = req.Body.Close()
					return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("<Envelope/>"))}, nil
				})},
			}
			got, pm := mapAndInjectUPnP(t.Context(), gw, raw, time.Minute)
			wantCalls := 0
			if ip.Is4() {
				wantCalls = 1
			}
			if got != raw || pm != nil || calls != wantCalls {
				t.Fatalf("unsupported or unavailable route altered direct SDP: %d calls, mapping %v / %q", calls, pm, got)
			}
		})
	}
}
