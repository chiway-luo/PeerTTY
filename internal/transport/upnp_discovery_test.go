package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestGatewayDiscoveryContinuesAfterUnavailableLocalRouter(t *testing.T) {
	const offline = "http://192.168.100.1/desc.xml"
	const working = "http://192.168.100.2/desc.xml"
	replies := []string{"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n", "LOCATION: " + offline, "Location: " + offline, "location: " + working}
	var investigated []string
	chosen := &upnpGateway{gatewayHost: netip.MustParseAddr("192.168.100.2")}
	got := awaitUPnPGateway(t.Context(), func(buf []byte) (int, *net.UDPAddr, error) {
		if len(replies) == 0 {
			t.Fatal("discovery did not stop after the usable router responded")
		}
		reply := replies[0]
		replies = replies[1:]
		return copy(buf, reply), nil, nil
	}, func(_ context.Context, url string, _ *http.Client) (*upnpGateway, error) {
		investigated = append(investigated, url)
		if url == working {
			return chosen, nil
		}
		return nil, errors.New("fixture router unavailable")
	})
	if got != chosen || !slices.Equal(investigated, []string{offline, working}) {
		t.Fatalf("gateway = %v; looked up %v", got, investigated)
	}
}

func TestGatewayDiscoveryReadFailureAndPreCanceledContext(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		if canceled {
			cancel()
		}
		calls := 0
		got := awaitUPnPGateway(ctx, func([]byte) (int, *net.UDPAddr, error) {
			calls++
			return 0, nil, io.EOF
		}, func(context.Context, string, *http.Client) (*upnpGateway, error) {
			t.Fatal("unexpected gateway description request")
			return nil, nil
		})
		cancel()
		if got != nil || (calls == 0) != canceled || calls > 1 {
			t.Fatalf("canceled=%v: got=%v reads=%d", canceled, got, calls)
		}
	}
}

func TestGatewayStatusDistinguishesMissingRouterFromMissingExternalAddress(t *testing.T) {
	host := netip.MustParseAddr("192.168.100.2")
	for _, tc := range []struct {
		name, reply, want string
		present           bool
	}{
		{"no gateway", "", "", false},
		{"gateway without address", "<Envelope/>", host.String(), true},
		{"gateway and address", "<NewExternalIPAddress>8.8.8.8</NewExternalIPAddress>", host.String() + "（出口 8.8.8.8）", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := &upnpGateway{
				gatewayHost: host,
				controlURL:  "http://" + host.String() + "/control",
				serviceType: upnpServiceTypes[0],
				client: &http.Client{Transport: fixtureGatewayRoundTripper(func(r *http.Request) (*http.Response, error) {
					defer r.Body.Close()
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.reply))}, nil
				})},
			}
			got, present := checkUPnPWith(t.Context(), func(context.Context) *upnpGateway {
				if !tc.present {
					return nil
				}
				return gw
			})
			if present != tc.present || got != tc.want {
				t.Fatalf("status=%q,%v; want=%q,%v", got, present, tc.want, tc.present)
			}
		})
	}
}
