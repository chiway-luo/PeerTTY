package transport

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

func TestRoamingEgressUsesOnlyNominatedPathAndClassifiesSendFailures(t *testing.T) {
	logicalConn, physicalConn := &socketLifecycleFixture{}, &socketLifecycleFixture{}
	logical := wirePath{&roamSocket{UDPConn: logicalConn}, netip.MustParseAddrPort("127.0.0.1:12001")}
	physical := wirePath{&roamSocket{UDPConn: physicalConn}, netip.MustParseAddrPort("127.0.0.1:12002")}
	r, _ := roamingPair(t, t.Context())
	r.physical = physical
	if used, err := r.write(logical, nil); used || err != nil || physicalConn.writes != 0 {
		t.Fatalf("empty write took over UDP path: %v/%v", used, err)
	}
	// A normal DTLS record type from the nominated ICE connection.
	record := []byte{22, 0xfe, 0xfd}
	if used, err := r.write(logical, record); !used || err != nil || physicalConn.writes != 1 {
		t.Fatalf("nominated packet did not use validated egress: %v/%v writes=%d", used, err, physicalConn.writes)
	}
	if !r.nominated || r.logical != logical || logicalConn.writes != 0 {
		t.Fatal("ICE selected socket was not preserved separately from the physical route")
	}
	other := wirePath{logical.socket, netip.MustParseAddrPort("127.0.0.1:12003")}
	if used, err := r.write(other, []byte("ordinary fixture datagram")); used || err != nil || physicalConn.writes != 1 {
		t.Fatalf("another candidate incorrectly took over nominated egress: %v/%v", used, err)
	}
	for _, tc := range []struct {
		name         string
		send, report error
	}{
		{name: "interface temporarily unavailable", send: syscall.ENETDOWN},
		{name: "old socket already closed", send: net.ErrClosed},
		{name: "unrelated socket failure returned to caller", send: syscall.EACCES, report: syscall.EACCES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := physicalConn.writes
			physicalConn.writeErr = tc.send
			used, err := r.write(logical, record)
			if !used || !errors.Is(err, tc.report) || physicalConn.writes != before+1 || logicalConn.writes != 0 {
				t.Fatalf("old path send = %v/%v; physical writes=%d, logical writes=%d", used, err, physicalConn.writes, logicalConn.writes)
			}
		})
	}
}

func TestRoamingLifecycleWithoutCompatiblePeerKeepsOrdinaryICE(t *testing.T) {
	r, err := newRoaming(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.enable(nil, func() bool { return false }); err != nil {
		t.Fatal(err)
	}
	if r.keys.Load() != nil || !r.started.IsZero() {
		t.Fatal("legacy peer incorrectly started route recovery")
	}
	r.close()
	r.close()
	select {
	case <-r.done:
	default:
		t.Fatal("roaming close did not signal owner shutdown")
	}
}
