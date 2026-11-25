package transport

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func startupRecord() []byte {
	return []byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}
}

func TestStartupCopiesRequireBoundLiveGrantAndStayBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r, _ := roamingPair(t, ctx)
	now := time.Now()
	unbound, err := newRoaming(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{nil, {22, 0xfe, 0xfd}, make([]byte, 20), {21, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if r.reserveStartupCopy(raw, now) {
			t.Fatal("copied a datagram outside the eligible DTLS records")
		}
	}
	if unbound.reserveStartupCopy(startupRecord(), now) {
		t.Fatal("sent an extra packet without a bound grant")
	}
	for range startupCopyLimit {
		if !r.reserveStartupCopy(startupRecord(), now) {
			t.Fatal("ran out of startup copies early")
		}
	}
	if r.reserveStartupCopy(startupRecord(), now) {
		t.Fatal("exceeded maximum startup copy budget")
	}
	fresh, _ := roamingPair(t, ctx)
	if !fresh.reserveStartupCopy(startupRecord(), now) || fresh.reserveStartupCopy(startupRecord(), now.Add(startupCopyWindow)) {
		t.Fatal("startup window did not close by elapsed time")
	}
	cancel()
	if fresh.reserveStartupCopy(startupRecord(), now) {
		t.Fatal("duplicated a packet after authorization ended")
	}
}

type startupUDPFixture struct {
	socketLifecycleFixture
	data   [][]byte
	to     []net.Addr
	failAt int
}

var errStartupSend = errors.New("fixture send failed")

func (f *startupUDPFixture) WriteTo(b []byte, dest net.Addr) (int, error) {
	f.data = append(f.data, bytes.Clone(b))
	f.to = append(f.to, dest)
	if len(f.data) == f.failAt {
		return 0, errStartupSend
	}
	return len(b), nil
}

func TestExtraStartupSendIsSameDatagramAndBestEffort(t *testing.T) {
	p := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:2200"))
	record := startupRecord()
	f := &startupUDPFixture{failAt: 2}
	n, err := writeStartupDatagram(f, record, p, true)
	if n != len(record) || err != nil || len(f.data) != 2 || !bytes.Equal(f.data[0], f.data[1]) || f.to[0] != f.to[1] {
		t.Fatalf("unexpected retry n=%d err=%v writes=%d", n, err, len(f.data))
	}
	f = &startupUDPFixture{failAt: 1}
	if _, err := writeStartupDatagram(f, record, p, true); !errors.Is(err, errStartupSend) || len(f.data) != 1 {
		t.Fatalf("primary send error suppressed or not respected: %v writes=%d", err, len(f.data))
	}
}

func TestMigratedStartupCopyUsesIdenticalAuthenticatedFrame(t *testing.T) {
	a, b := roamingPair(t, t.Context())
	physical := &startupUDPFixture{}
	logical := &socketLifecycleFixture{}
	a.physical = wirePath{&roamSocket{UDPConn: physical}, netip.MustParseAddrPort("192.0.2.1:2200")}
	path := wirePath{&roamSocket{UDPConn: logical}, netip.MustParseAddrPort("192.0.2.2:2200")}
	record := startupRecord()
	if used, err := a.write(path, record); !used || err != nil || logical.writes != 0 || len(physical.data) != 2 || !bytes.Equal(physical.data[0], physical.data[1]) {
		t.Fatalf("duplicate did not use the exact validated wire path: %v / %v", used, err)
	}
	frame, ok := b.keys.Load().decrypt(physical.data[0])
	if !ok || frame.kind != pathData || !bytes.Equal(frame.body, record) ||
		!b.keys.Load().accept(frame.seq) || b.keys.Load().accept(frame.seq) {
		t.Fatal("invalid protected packet or duplicate was not replay-filtered")
	}
}
