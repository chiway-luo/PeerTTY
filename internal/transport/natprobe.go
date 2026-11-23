package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v4"
)

const probeTimeout = 3 * time.Second

// MappingProbe is one STUN server's view of the probe socket.
type MappingProbe struct {
	Server   string
	Endpoint netip.AddrPort
	Mapped   netip.AddrPort
	Err      error
}

// NATReport compares the mappings that different servers observe for the
// same local UDP port. ICE gathers each server on a separate socket, so its
// candidates cannot reveal destination-dependent (symmetric) mapping.
type NATReport struct {
	Local  netip.AddrPort
	Probes []MappingProbe
}

type NATBehavior int

const (
	NATUnknown NATBehavior = iota
	NATNoResponse
	NATSingleServer
	NATEndpointIndependent
	NATAddressDependent
	NATPortDependent
)

func (r NATReport) Behavior() NATBehavior {
	var first netip.AddrPort
	seen := make(map[netip.AddrPort]bool)
	addressChanged, portChanged := false, false
	attempted := false
	for _, p := range r.Probes {
		if !errors.Is(p.Err, errIPv6Probe) {
			attempted = true
		}
		if p.Err != nil || !p.Mapped.IsValid() || !p.Endpoint.IsValid() || seen[p.Endpoint] {
			continue
		}
		seen[p.Endpoint] = true
		if !first.IsValid() {
			first = p.Mapped
		}
		portChanged = portChanged || p.Mapped.Port() != first.Port()
		addressChanged = addressChanged || p.Mapped.Addr() != first.Addr()
	}
	switch {
	case !attempted:
		return NATUnknown
	case len(seen) == 0:
		return NATNoResponse
	case len(seen) == 1:
		return NATSingleServer
	case portChanged:
		return NATPortDependent
	case addressChanged:
		return NATAddressDependent
	default:
		return NATEndpointIndependent
	}
}

// Verdict explains the result for the person diagnosing a failed pairing.
func (r NATReport) Verdict() string {
	switch r.Behavior() {
	case NATNoResponse:
		return "所有 STUN 服务器都未响应。出站 UDP 可能被封锁，或这些地址在当前网络不可达。"
	case NATSingleServer:
		return "只有一台 STUN 服务器响应，无法判断映射是否随目的地变化。可在连接设置中再添加一个可达的 STUN 地址。"
	case NATEndpointIndependent:
		if len(r.Probes) > 0 && publicIPv4(r.Local.Addr()) && r.firstMapped() == r.Local {
			return "映射与本机地址一致，本机可能直接持有公网地址。"
		}
		return "同一本地端口在不同服务器看到的映射一致，适合 UDP 打洞。"
	case NATAddressDependent:
		return "不同服务器看到的出口 IP 不同（多出口地址池）。端口一致时多数可以打洞，失败时可换一个网络重试。"
	case NATPortDependent:
		return "同一本地端口对不同服务器映射到不同端口，疑似对称型 NAT。若另一端也是这种网络，直连很可能失败，建议一端换用手机热点或其他网络。"
	default:
		return ""
	}
}

func (r NATReport) firstMapped() netip.AddrPort {
	for _, p := range r.Probes {
		if p.Err == nil && p.Mapped.IsValid() {
			return p.Mapped
		}
	}
	return netip.AddrPort{}
}

// ProbeNAT sends Binding requests to every configured IPv4 STUN server from a
// single socket. It never contacts a peer and changes no network settings.
func ProbeNAT(parent context.Context, spec string) (NATReport, error) {
	urls, err := STUNServers(spec)
	if err != nil || len(urls) == 0 {
		return NATReport{}, err
	}
	ctx, cancel := context.WithTimeout(parent, probeTimeout+2*time.Second)
	defer cancel()
	servers := make([]probeTarget, len(urls))
	var wg sync.WaitGroup
	for i, raw := range urls {
		servers[i] = probeTarget{name: raw}
		uri, err := stun.ParseURI(raw)
		if err != nil {
			servers[i].err = err
			continue
		}
		if ip, parseErr := netip.ParseAddr(uri.Host); parseErr == nil {
			ip = ip.Unmap()
			if !ip.Is4() {
				servers[i].err = errIPv6Probe
				continue
			}
			servers[i].addr = netip.AddrPortFrom(ip, uint16(uri.Port))
			continue
		}
		wg.Add(1)
		go func(idx int, host string, port int) {
			defer wg.Done()
			resolveCtx, stop := context.WithTimeout(ctx, probeTimeout)
			defer stop()
			addrs, err := net.DefaultResolver.LookupNetIP(resolveCtx, "ip4", host)
			if err != nil || len(addrs) == 0 {
				servers[idx].err = fmt.Errorf("无法解析 IPv4 地址: %w", errors.Join(err, errNoIPv4))
				return
			}
			servers[idx].addr = netip.AddrPortFrom(addrs[0].Unmap(), uint16(port))
		}(i, uri.Host, uri.Port)
	}
	wg.Wait()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return NATReport{}, err
	}
	defer conn.Close()
	return probeMappings(ctx, conn, servers, 500*time.Millisecond), nil
}

var errIPv6Probe = errors.New("IPv6 地址不参与 IPv4 NAT 类型检测")

var errNoIPv4 = errors.New("no IPv4 address")

type probeTarget struct {
	name string
	addr netip.AddrPort
	err  error
}

func probeMappings(ctx context.Context, conn *net.UDPConn, servers []probeTarget, retry time.Duration) NATReport {
	report := NATReport{Probes: make([]MappingProbe, len(servers))}
	if local, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		report.Local = local.AddrPort()
	}
	pending := make(map[[stun.TransactionIDSize]byte]int)
	requests := make([][]byte, len(servers))
	firstTarget := make(map[netip.AddrPort]int)
	for i, s := range servers {
		report.Probes[i] = MappingProbe{Server: s.name, Endpoint: s.addr, Err: s.err}
		if s.err != nil {
			continue
		}
		if _, duplicate := firstTarget[s.addr]; duplicate {
			continue
		}
		firstTarget[s.addr] = i
		msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		pending[msg.TransactionID] = i
		requests[i] = msg.Raw
		report.Probes[i].Err = errors.New("超时未响应")
	}
	send := func() {
		for _, i := range pending {
			_, _ = conn.WriteToUDPAddrPort(requests[i], servers[i].addr)
		}
	}
	deadline := time.Now().Add(probeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	buf := make([]byte, 1500)
	next := time.Now()
	for len(pending) > 0 && time.Now().Before(deadline) && ctx.Err() == nil {
		if !time.Now().Before(next) {
			send()
			next = time.Now().Add(retry)
		}
		_ = conn.SetReadDeadline(minTime(next, deadline))
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			continue
		}
		msg := stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if msg.Decode() != nil || msg.Type != stun.BindingSuccess {
			continue
		}
		i, ok := pending[msg.TransactionID]
		if !ok || from.Addr().Unmap() != servers[i].addr.Addr() || from.Port() != servers[i].addr.Port() {
			continue
		}
		var xor stun.XORMappedAddress
		if err := xor.GetFrom(&msg); err != nil {
			var plain stun.MappedAddress
			if plain.GetFrom(&msg) != nil {
				continue
			}
			xor.IP, xor.Port = plain.IP, plain.Port
		}
		ip, ok := netip.AddrFromSlice(xor.IP)
		if !ok {
			continue
		}
		report.Probes[i].Mapped = netip.AddrPortFrom(ip.Unmap(), uint16(xor.Port))
		report.Probes[i].Err = nil
		delete(pending, msg.TransactionID)
	}
	for i, s := range servers {
		if j, ok := firstTarget[s.addr]; ok && i != j {
			report.Probes[i].Mapped, report.Probes[i].Err = report.Probes[j].Mapped, report.Probes[j].Err
		}
		if report.Local.Addr().IsUnspecified() && report.Probes[i].Mapped.IsValid() {
			if ip, ok := sourceIPv4(s.addr); ok {
				report.Local = netip.AddrPortFrom(ip, report.Local.Port())
			}
		}
	}
	return report
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (p MappingProbe) String() string {
	name := strings.TrimPrefix(p.Server, "stun:")
	if p.Err != nil {
		return name + " · " + p.Err.Error()
	}
	return name + " · 映射 " + net.JoinHostPort(p.Mapped.Addr().String(), strconv.Itoa(int(p.Mapped.Port())))
}
