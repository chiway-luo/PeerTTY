package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestGatherMappingLeavesDescriptionUntouchedWithoutRouter(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p := &Peer{lifetime: ctx}
	gateways := make(chan *upnpGateway, 1)
	inject := func(context.Context, *upnpGateway, string, time.Duration) (string, *portMapping) {
		t.Fatal("mapping started with no router or a canceled discovery")
		return "", nil
	}
	gateways <- nil
	if desc, err := p.gatherMapping(ctx, gateways, "fixture description", inject); err != nil || desc != "fixture description" || p.portMap != nil {
		t.Fatalf("missing router affected direct path: %q, %v", desc, err)
	}
	cancel()
	if desc, err := p.gatherMapping(ctx, gateways, "fixture description", inject); !errors.Is(err, context.Canceled) || desc != "" {
		t.Fatalf("canceling discovery: %q, %v", desc, err)
	}
}

func TestGatherMappingOwnsOrReleasesRouterLease(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		deadline, want        time.Duration
		hasDeadline, shutdown bool
		noMapping             bool
	}{
		{name: "default lease", want: time.Hour},
		{name: "lease follows grant expiration", hasDeadline: true, deadline: 12 * time.Minute, want: 12 * time.Minute},
		{name: "expired grant timestamp uses existing fallback", hasDeadline: true, deadline: -time.Second, want: time.Hour, noMapping: true},
		{name: "late mapping released on shutdown", shutdown: true, want: time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var lifetime context.Context = t.Context()
				if tc.hasDeadline {
					var cancel context.CancelFunc
					lifetime, cancel = context.WithDeadline(lifetime, time.Now().Add(tc.deadline))
					defer cancel()
				}
				p, err := New(lifetime, "none")
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				gateways := make(chan *upnpGateway, 1)
				deletions := 0
				gw := &upnpGateway{controlURL: "http://192.168.100.1/control", serviceType: upnpServiceTypes[0],
					client: &http.Client{Transport: fixtureGatewayRoundTripper(func(r *http.Request) (*http.Response, error) {
						defer r.Body.Close()
						body, err := io.ReadAll(r.Body)
						if err != nil || !strings.HasSuffix(r.Header.Get("SOAPAction"), "#DeletePortMapping\"") ||
							!strings.Contains(string(body), "<NewExternalPort>51234</NewExternalPort>") {
							t.Fatalf("wrong cleanup call: %s / %s / %v", r.Header, body, err)
						}
						deletions++
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<Envelope/>"))}, nil
					})}}
				pm := &portMapping{gateway: gw, external: netip.MustParseAddrPort("192.0.2.1:51234")}
				gateways <- gw
				ctx := t.Context()
				wantText := "mapped fixture description"
				if tc.noMapping {
					wantText = "fixture description"
				}
				got, err := p.gatherMapping(ctx, gateways, "fixture description", func(gotCtx context.Context, gotGW *upnpGateway, desc string, lease time.Duration) (string, *portMapping) {
					if gotCtx != ctx || gotGW != gw || desc != "fixture description" || lease != tc.want {
						t.Fatalf("unexpected mapping input: ctx match %v, gateway match %v, description %q, lease %v", gotCtx == ctx, gotGW == gw, desc, lease)
					}
					if tc.noMapping {
						return desc, nil
					}
					// Represent shutdown reaching its synchronized state before the
					// in-flight mapping request returns its lease.
					if tc.shutdown {
						if err := p.Close(); err != nil {
							t.Fatal(err)
						}
					}
					return "mapped " + desc, pm
				})
				if err != nil || got != wantText {
					t.Fatalf("mapping result: %q / %v", got, err)
				}
				switch {
				case tc.shutdown:
					if p.portMap != nil || deletions != 1 {
						t.Fatalf("late mapping leaked: %v / %d deletions", p.portMap, deletions)
					}
				case tc.noMapping:
					if p.portMap != nil || deletions != 0 {
						t.Fatal("failed mapping modified peer state")
					}
				default:
					if p.portMap != pm || deletions != 0 {
						t.Fatal("peer did not retain mapping for cleanup on close")
					}
					if err := p.Close(); err != nil || p.portMap != nil || deletions != 1 {
						t.Fatalf("closing peer did not clear and release mapping exactly once: %v / %v / %d", err, p.portMap, deletions)
					}
				}
			})
		})
	}
}

func TestClosedPeerRejectsPreparedRemoteDescriptions(t *testing.T) {
	other, err := New(t.Context(), "none")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	offer, err := other.Offer(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewGrant(t.Context(), "none")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if answer, err := p.Answer(t.Context(), offer); err == nil || answer != "" || p.CanRoam() {
		t.Fatalf("closed peer accepted an offer: %q / %v", answer, err)
	}
}
