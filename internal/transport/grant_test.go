package transport

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pion/datachannel"
)

func TestGrantOpensIndependentTerminalStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("opens terminal streams between two WebRTC peers")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	host, err := NewGrant(ctx, "none")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	control, err := NewGrant(ctx, "none")
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	offer, err := host.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := control.Answer(ctx, offer)
	if err != nil {
		t.Fatal(err)
	}
	if err = host.Accept(answer); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []*Peer{host, control} {
		channel, route, err := peer.Channel(ctx)
		if err != nil || channel == nil || !strings.HasPrefix(route, "udp ") || !peer.Connected() {
			t.Fatalf("direct path: %q %v", route, err)
		}
	}
	incoming := make(chan datachannel.ReadWriteCloserDeadliner, 2)
	host.OnLink(func(c datachannel.ReadWriteCloserDeadliner) { incoming <- c })
	var remote []datachannel.ReadWriteCloserDeadliner
	for _, msg := range []string{"one", "two"} {
		c, err := control.OpenLink(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		select {
		case h := <-incoming:
			remote = append(remote, h)
			defer h.Close()
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		deadline, _ := ctx.Deadline()
		if err = c.SetWriteDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(c, msg); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range []string{"one", "two"} {
		deadline, _ := ctx.Deadline()
		if err := remote[i].SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		var buf [32]byte
		n, err := remote[i].Read(buf[:])
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("terminal %d: %q %v", i, buf[:n], err)
		}
	}
}

func TestUnconnectedGrantHonorsCancellation(t *testing.T) {
	p, err := NewGrant(t.Context(), "none")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = p.OpenLink(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("link: %v", err)
	}
	if _, _, err = p.Channel(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("channel: %v", err)
	}
	if p.Connected() {
		t.Fatal("unpaired peer reports a connection")
	}
}

func TestDiscoveryCountsOnlyUsableDataCandidates(t *testing.T) {
	const header = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
	var s strings.Builder
	s.WriteString(header)
	for _, spec := range []string{
		"1 1 udp 1 192.0.2.2 4100 typ host", "2 1 udp 1 2001:db8::2 4100 typ host",
		"3 1 udp 1 198.51.100.3 4101 typ srflx raddr 192.0.2.2 rport 4100",
		"4 2 udp 1 192.0.2.2 4100 typ host", "5 1 udp 1 127.0.0.1 4100 typ host",
		"6 1 udp 1 :: 4100 typ host", "7 1 tcp 1 192.0.2.2 4100 typ host tcptype passive", "invalid",
	} {
		s.WriteString("a=candidate:" + spec + "\r\n")
	}
	want := Candidates{IPv4: 1, IPv6: 1, Mapped: 1, TCP: 1}
	if got := CountCandidates(s.String()); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := CountCandidates("invalid"); got != (Candidates{}) {
		t.Fatalf("invalid SDP: %+v", got)
	}
}
