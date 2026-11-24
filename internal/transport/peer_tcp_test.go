package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pion/ice/v4"
)

// Give the other peer only our actual loopback TCP listener. This exercises
// the normal offer/answer and data channels without relying on a host firewall.
func tcpLoopbackSDP(t *testing.T, raw string) (string, string) {
	t.Helper()
	var out strings.Builder
	var address string
	for _, line := range strings.SplitAfter(raw, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "a=candidate:"); ok {
			c, err := ice.UnmarshalCandidate(value)
			if err != nil {
				t.Fatal(err)
			}
			if c.Component() != 1 || c.NetworkType() != ice.NetworkTypeTCP4 ||
				c.TCPType() != ice.TCPTypePassive || c.Address() != "127.0.0.1" {
				continue
			}
			address = netip.AddrPortFrom(netip.MustParseAddr(c.Address()), uint16(c.Port())).String()
		}
		out.WriteString(line)
	}
	if address == "" {
		t.Fatal("no passive TCP candidate on the IPv4 loopback")
	}
	return out.String(), address
}

func TestDirectTCPTransports(t *testing.T) {
	if testing.Short() {
		t.Skip("opens two local ICE-TCP peers")
	}
	for _, tc := range []struct {
		name string
		new  func(context.Context, string) (*Peer, error)
	}{{"one shot", New}, {"multiple terminals", NewGrant}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 12*time.Second)
			defer stop()
			host, err := tc.new(ctx, "none")
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			controller, err := tc.new(ctx, "none")
			if err != nil {
				t.Fatal(err)
			}
			defer controller.Close()
			offer, err := host.Offer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			offer, hostAddr := tcpLoopbackSDP(t, offer)
			answer, err := controller.Answer(ctx, offer)
			if err != nil {
				t.Fatal(err)
			}
			answer, controllerAddr := tcpLoopbackSDP(t, answer)
			if err := host.Accept(answer); err != nil {
				t.Fatal(err)
			}
			var receipt [ed25519.SignatureSize]byte
			rand.Read(receipt[:])
			for _, p := range []*Peer{host, controller} {
				if err := p.BindGrant(receipt[:]); err != nil {
					t.Fatal(err)
				}
			}
			local, hostRoute, err := host.Channel(ctx)
			if err != nil {
				t.Fatal(err)
			}
			remote, controllerRoute, err := controller.Channel(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(hostRoute, "tcp ") || !strings.HasPrefix(controllerRoute, "tcp ") ||
				host.CanRoam() || controller.CanRoam() || host.Migrated() || controller.Migrated() {
				t.Fatalf("expected direct TCP without UDP migration: host=%q controller=%q", hostRoute, controllerRoute)
			}
			deadline, _ := ctx.Deadline()
			if err := remote.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if _, err := local.Write([]byte("terminal")); err != nil {
				t.Fatal(err)
			}
			var buf [16]byte
			n, err := remote.Read(buf[:])
			if err != nil || string(buf[:n]) != "terminal" {
				t.Fatalf("received %q: %v", buf[:n], err)
			}
			for p, addr := range map[*Peer]string{host: hostAddr, controller: controllerAddr} {
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
				if c, err := net.DialTimeout("tcp4", addr, time.Second); err == nil {
					c.Close()
					t.Fatalf("TCP listener %s still active after closing peer", addr)
				}
			}
		})
	}
}
