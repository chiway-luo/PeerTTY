package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pion/stun/v4"
)

func startFakeSTUN(t *testing.T, reply func(sender *net.UDPAddr) (net.IP, int, bool)) netip.AddrPort {
	t.Helper()
	return startFakeSTUNWith(t, func(from *net.UDPAddr) stun.Setter {
		ip, port, ok := reply(from)
		if !ok {
			return nil
		}
		return &stun.XORMappedAddress{IP: ip, Port: port}
	})
}

func startFakeSTUNWith(t *testing.T, reply func(sender *net.UDPAddr) stun.Setter) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := stun.Message{Raw: buf[:n]}
			if req.Decode() != nil || req.Type != stun.BindingRequest {
				continue
			}
			attr := reply(from)
			if attr == nil {
				continue
			}
			resp, err := stun.Build(stun.NewTransactionIDSetter(req.TransactionID), stun.BindingSuccess, attr)
			if err == nil {
				_, _ = conn.WriteToUDP(resp.Raw, from)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestProbeNATDetectsBehavior(t *testing.T) {
	s1 := startFakeSTUN(t, func(*net.UDPAddr) (net.IP, int, bool) {
		return net.IPv4(198, 51, 100, 10), 40001, true
	})
	s2Same := startFakeSTUN(t, func(*net.UDPAddr) (net.IP, int, bool) {
		return net.IPv4(198, 51, 100, 10), 40001, true
	})
	s2DiffPort := startFakeSTUN(t, func(*net.UDPAddr) (net.IP, int, bool) {
		return net.IPv4(198, 51, 100, 10), 40002, true
	})
	s2DiffIP := startFakeSTUN(t, func(*net.UDPAddr) (net.IP, int, bool) {
		return net.IPv4(198, 51, 100, 11), 40001, true
	})
	silent := startFakeSTUN(t, func(*net.UDPAddr) (net.IP, int, bool) {
		return nil, 0, false
	})

	for _, tc := range []struct {
		name    string
		servers []netip.AddrPort
		want    NATBehavior
		verdict string
	}{
		{"endpoint independent", []netip.AddrPort{s1, s2Same}, NATEndpointIndependent, "适合 UDP 打洞"},
		{"symmetric port dependent", []netip.AddrPort{s1, s2DiffPort}, NATPortDependent, "对称型 NAT"},
		{"address pool", []netip.AddrPort{s1, s2DiffIP}, NATAddressDependent, "出口 IP 不同"},
		{"single responder", []netip.AddrPort{s1, silent}, NATSingleServer, "只有一台 STUN"},
		{"two names of one endpoint", []netip.AddrPort{s1, s1}, NATSingleServer, "只有一台 STUN"},
		{"address change first", []netip.AddrPort{s1, s2DiffIP, s2DiffPort}, NATPortDependent, "对称型 NAT"},
		{"port change first", []netip.AddrPort{s1, s2DiffPort, s2DiffIP}, NATPortDependent, "对称型 NAT"},
		{"no response", []netip.AddrPort{silent}, NATNoResponse, "都未响应"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var targets []probeTarget
			for _, ap := range tc.servers {
				targets = append(targets, probeTarget{name: "stun:" + ap.String(), addr: ap})
			}
			report := probeMappings(ctx, conn, targets, 50*time.Millisecond)
			if got := report.Behavior(); got != tc.want {
				t.Fatalf("Behavior() = %v, want %v (probes=%+v)", got, tc.want, report.Probes)
			}
			if !strings.Contains(report.Verdict(), tc.verdict) {
				t.Fatalf("Verdict() = %q, want substring %q", report.Verdict(), tc.verdict)
			}
		})
	}
}

func TestProbeNATNoneAndDirectPublicIP(t *testing.T) {
	report, err := ProbeNAT(t.Context(), "none")
	if err != nil || report.Behavior() != NATUnknown || report.Verdict() != "" {
		t.Fatalf("none: report=%+v err=%v", report, err)
	}
	if _, err := ProbeNAT(t.Context(), "http://bad"); err == nil {
		t.Fatal("accepted invalid STUN spec")
	}
	local := netip.MustParseAddrPort("8.8.4.4:5555")
	direct := NATReport{
		Local: local,
		Probes: []MappingProbe{
			{Server: "stun:a:3478", Endpoint: netip.MustParseAddrPort("127.0.0.1:1234"), Mapped: local},
			{Server: "stun:b:3478", Endpoint: netip.MustParseAddrPort("127.0.0.1:5678"), Mapped: local},
		},
	}
	if !strings.Contains(direct.Verdict(), "公网地址") {
		t.Fatalf("direct public IP verdict = %q", direct.Verdict())
	}
	if got := direct.Probes[0].String(); !strings.Contains(got, "a:3478") || !strings.Contains(got, "8.8.4.4:5555") {
		t.Fatalf("probe string = %q", got)
	}
	failed := MappingProbe{Server: "stun:dead:3478", Err: errors.New("超时未响应")}
	if !strings.Contains(failed.String(), "dead:3478") || !strings.Contains(failed.String(), "超时") {
		t.Fatalf("failed probe string = %q", failed.String())
	}
}

func TestCompactSDPStripsComponent2(t *testing.T) {
	raw := strings.Join([]string{
		"v=0",
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
		"a=candidate:1 1 udp 2130706431 192.0.2.1 50000 typ host generation 0",
		"a=candidate:1 2 udp 2130706430 192.0.2.1 50000 typ host generation 0",
		"a=candidate:2 1 udp 1694498815 198.51.100.2 50001 typ srflx raddr 192.0.2.1 rport 50000 generation 0",
		"a=candidate:2 2 udp 1694498814 198.51.100.2 50001 typ srflx raddr 192.0.2.1 rport 50000 generation 0",
		"a=end-of-candidates",
		"",
	}, "\r\n")
	got := compactSDP(raw)
	if strings.Contains(got, " 2 udp ") {
		t.Fatalf("component 2 candidate remained:\n%s", got)
	}
	if strings.Count(got, "a=candidate:") != 2 {
		t.Fatalf("expected 2 component-1 candidates, got:\n%s", got)
	}
}

func TestProbeNATEndToEndLocalServersAndHasRemoteSTUN(t *testing.T) {
	s1 := startFakeSTUN(t, func(*net.UDPAddr) (net.IP, int, bool) {
		return net.IPv4(198, 51, 100, 20), 41001, true
	})
	s2 := startFakeSTUN(t, func(*net.UDPAddr) (net.IP, int, bool) {
		return net.IPv4(198, 51, 100, 20), 41002, true
	})
	spec := "stun:" + s1.String() + ",stun:" + s2.String() + ",stun:[::1]:3478"
	report, err := ProbeNAT(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if report.Behavior() != NATPortDependent || len(report.Probes) != 3 {
		t.Fatalf("ProbeNAT behavior=%v probes=%+v", report.Behavior(), report.Probes)
	}
	if report.Probes[2].Err == nil || !strings.Contains(report.Probes[2].Err.Error(), "IPv6") {
		t.Fatalf("expected IPv6 skip error, got %+v", report.Probes[2])
	}

	if hasRemoteSTUN([]string{"stun:127.0.0.1:3478", "stun:[::1]:3478", "stun:localhost:3478"}) {
		t.Fatal("loopback STUN reported as remote")
	}
	if !hasRemoteSTUN([]string{"stun:127.0.0.1:3478", "stun:stun.cloudflare.com:3478"}) {
		t.Fatal("remote STUN not detected")
	}
	if !hasRemoteSTUN([]string{"stun:198.51.100.1:3478"}) {
		t.Fatal("remote IPv4 STUN not detected")
	}
}

func TestNATReportIgnoresIncompleteObservations(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.1:3478")
	mapped := netip.MustParseAddrPort("198.51.100.1:55000")
	ok := MappingProbe{Endpoint: endpoint, Mapped: mapped}
	bad := []MappingProbe{
		{Err: errIPv6Probe, Endpoint: endpoint, Mapped: mapped},
		{Endpoint: endpoint},
		{Mapped: mapped},
	}
	report := NATReport{Probes: bad}
	if got := report.Behavior(); got != NATNoResponse {
		t.Fatalf("incomplete observations counted as replies: got %v", got)
	}
	if got := (NATReport{Probes: bad[:2]}).firstMapped(); got.IsValid() {
		t.Fatalf("failed or missing observations returned a mapping: %v", got)
	}
	report.Probes = append(report.Probes, ok, MappingProbe{Endpoint: endpoint, Mapped: netip.MustParseAddrPort("198.51.100.2:5000")})
	if got := report.Behavior(); got != NATSingleServer {
		t.Fatalf("one unique successful endpoint counted as %v", got)
	}
	if got := (NATReport{Probes: bad[:1]}).Behavior(); got != NATUnknown {
		t.Fatalf("IPv6-only unsupported entries counted as attempts: %v", got)
	}
	if got := (NATReport{}).firstMapped(); got.IsValid() {
		t.Fatalf("empty report unexpectedly has mapping: %v", got)
	}
}

func TestNATVerdictDistinguishesPublicAddressFromStableMapping(t *testing.T) {
	mapped := netip.MustParseAddrPort("198.51.100.1:55000")
	report := NATReport{Probes: []MappingProbe{
		{Endpoint: netip.MustParseAddrPort("192.0.2.1:3478"), Mapped: mapped},
		{Endpoint: netip.MustParseAddrPort("192.0.2.2:3478"), Mapped: mapped},
	}}
	for _, local := range []string{"192.168.1.4:55000", "8.8.4.4:55000"} {
		report.Local = netip.MustParseAddrPort(local)
		if got := report.Verdict(); !strings.Contains(got, "映射一致") || strings.Contains(got, "持有公网地址") {
			t.Errorf("local %s with distinct stable mapping: %q", local, got)
		}
	}
}
