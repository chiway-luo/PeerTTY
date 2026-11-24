package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/pion/stun/v4"
)

func TestProbeTargetsKeepConfiguredOrderAndPerServerErrors(t *testing.T) {
	cause := errors.New("fixture resolver unavailable")
	entries := []string{
		"stun:192.0.2.10:3478",
		"stun:resolved.test:4000",
		"stun:[::1]:3478",
		"stun:missing.test:3478",
		"stun:empty.test:3478",
		"not a STUN URI",
		"stun:[::ffff:192.0.2.11]:3478",
	}
	got := resolveProbeTargets(t.Context(), entries, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip4" {
			return nil, errors.New("fixture: lookup was not IPv4 only")
		}
		if d, ok := ctx.Deadline(); !ok || time.Until(d) > probeTimeout {
			return nil, errors.New("fixture: DNS lookup was not bounded")
		}
		switch host {
		case "resolved.test":
			return []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")}, nil
		case "missing.test":
			return nil, cause
		case "empty.test":
			return nil, nil
		default:
			return nil, errors.New("fixture: unexpected hostname")
		}
	})
	if len(got) != len(entries) {
		t.Fatalf("lost configured entries: %+v", got)
	}
	for i, entry := range entries {
		if got[i].name != entry {
			t.Fatalf("configured endpoint %d reordered or renamed: %+v", i, got[i])
		}
	}
	for i, want := range map[int]string{0: "192.0.2.10:3478", 1: "198.51.100.1:4000", 6: "192.0.2.11:3478"} {
		if got[i].err != nil || got[i].addr != netip.MustParseAddrPort(want) {
			t.Fatalf("target %d = %+v, want %s", i, got[i], want)
		}
	}
	_, invalidURI := stun.ParseURI(entries[5])
	if invalidURI == nil || !errors.Is(got[2].err, errIPv6Probe) || !errors.Is(got[3].err, cause) ||
		!errors.Is(got[3].err, errNoIPv4) || !errors.Is(got[4].err, errNoIPv4) ||
		!errors.Is(got[5].err, invalidURI) {
		t.Fatalf("lost categorized diagnostic errors: %+v", got)
	}
}

func TestProbeNATUsesLegacyMappingAndDeduplicatesLocalServerAliases(t *testing.T) {
	want := netip.MustParseAddrPort("198.51.100.7:43000")
	server := startFakeSTUNWith(t, func(*net.UDPAddr) stun.Setter {
		return &stun.MappedAddress{IP: net.IP(want.Addr().AsSlice()), Port: int(want.Port())}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	report, err := ProbeNAT(ctx, "stun:localhost:"+strconv.Itoa(int(server.Port()))+",stun:"+server.String())
	if err != nil || len(report.Probes) != 2 || report.Behavior() != NATSingleServer || !report.Local.Addr().IsLoopback() {
		t.Fatalf("legacy mapping did not yield one local responder: %+v / %v", report, err)
	}
	for _, probe := range report.Probes {
		if probe.Err != nil || probe.Endpoint != server || probe.Mapped != want {
			t.Fatalf("legacy mapping lost for server alias: %+v", probe)
		}
	}
}
