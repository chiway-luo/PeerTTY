package transport

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5"
)

func TestRoamingKeepsInitialICEPairAndBoundsLateReceiptRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, _ := roamingPair(t, t.Context())
		now := time.Now()
		a.started = now
		a.initialChecks = make(map[wirePath]time.Time)
		logical := wirePath{&roamSocket{}, netip.MustParseAddrPort("127.0.0.1:14001")}
		second := wirePath{&roamSocket{}, netip.MustParseAddrPort("127.0.0.1:14002")}
		check := stun.MustBuild(stun.TransactionID, stun.BindingRequest,
			stun.NewUsername("fixture:peer"), stun.NewShortTermIntegrity("test fixture password"))
		discovery := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		for _, b := range [][]byte{[]byte("ordinary data"), discovery.Raw} {
			if used, err := a.write(logical, b); used || err != nil || a.logical.socket != nil {
				t.Fatalf("ordinary application/discovery traffic elected a pair: %v / %v", used, err)
			}
		}
		for _, pair := range []wirePath{logical, second} {
			if used, err := a.write(pair, check.Raw); used || err != nil || a.logical != logical {
				t.Fatalf("initial checklist did not keep its first logical pair: %v / %v", used, err)
			}
		}
		if len(a.initialChecks) != 0 {
			t.Fatal("initial negotiation was unnecessarily throttled")
		}
		time.Sleep(9 * time.Second)
		if used, err := a.write(logical, check.Raw); used || err != nil {
			t.Fatalf("first late ICE check was suppressed: %v / %v", used, err)
		}
		if used, err := a.write(logical, check.Raw); !used || err != nil {
			t.Fatalf("immediate retry was not rate limited: %v / %v", used, err)
		}
		time.Sleep(3 * time.Second)
		if used, err := a.write(logical, check.Raw); used || err != nil {
			t.Fatalf("eligible retry was suppressed: %v / %v", used, err)
		}
		_, _ = a.write(second, []byte{22, 0xfe, 0xfd})
		if a.logical != second || !a.nominated || a.initialChecks != nil {
			t.Fatal("normal DTLS nomination did not retire pre-handshake state")
		}
	})
}

type routeDatagrams struct {
	transport.UDPConn
	payloads [][]byte
}

func (s *routeDatagrams) WriteTo(p []byte, _ net.Addr) (int, error) {
	s.payloads = append(s.payloads, slices.Clone(p))
	return len(p), nil
}

func TestRoamingAnswersOrdinaryPeerPathCheckAndRequestsReturnProof(t *testing.T) {
	a, b := roamingPair(t, t.Context())
	s := &routeDatagrams{}
	src := wirePath{&roamSocket{UDPConn: s}, netip.MustParseAddrPort("127.0.0.1:14003")}
	var token [16]byte
	copy(token[:], "path-check")
	b.receive(src, a.keys.Load().seal(pathChallenge, token[:]))
	if len(s.payloads) != 2 {
		t.Fatalf("one legitimate check should yield echo and reciprocal check, got %d", len(s.payloads))
	}
	response, ok := a.keys.Load().decrypt(s.payloads[0])
	if !ok || response.kind != pathResponse || !slices.Equal(response.body, token[:]) {
		t.Fatalf("response did not echo this peer's path check: %v", ok)
	}
	probe, ok := a.keys.Load().decrypt(s.payloads[1])
	own := b.challenges[src]
	if !ok || probe.kind != pathChallenge || !slices.Equal(probe.body, own.token[:]) {
		t.Fatalf("did not request a reciprocal check: %v", ok)
	}
	if len(b.confirmed) != 0 || b.physical.socket != nil {
		t.Fatal("one-way check incorrectly confirmed a route")
	}
}

func TestRoamingRecentConfirmedRoutesStayBoundedAndPreferHealthyCurrentPath(t *testing.T) {
	a, b := roamingPair(t, t.Context())
	socket := &roamSocket{}
	addr := netip.MustParseAddr("127.0.0.1")
	at := time.Now()
	b.logical = wirePath{socket, netip.AddrPortFrom(addr, 14000)}
	current := wirePath{socket, netip.AddrPortFrom(addr, 14001)}
	b.physical, b.lastProof = current, at
	b.confirmed[current] = at
	b.recent = append(b.recent, current.addr)
	for i := uint16(0); i < 63; i++ {
		path := wirePath{socket, netip.AddrPortFrom(addr, 14100+i)}
		b.confirmed[path] = at
		if i < 15 {
			b.recent = append(b.recent, path.addr)
		}
	}
	deliverResponse := func(path wirePath) {
		ch := routeChallenge{issued: time.Now()}
		b.challenges[path] = ch
		b.receive(path, a.keys.Load().seal(pathResponse, ch.token[:]))
	}
	another := wirePath{socket, netip.AddrPortFrom(addr, 14140)}
	deliverResponse(another)
	if len(b.confirmed) != 64 || len(b.recent) != 16 || b.recent[15] != another.addr ||
		slices.Contains(b.recent, current.addr) || b.physical != current {
		t.Fatal("confirmed alternate path grew cache, evicted the wrong entry, or displaced healthy route")
	}
	deliverResponse(another)
	if len(b.recent) != 16 || b.recent[15] != another.addr {
		t.Fatal("rechecking same route duplicated a recent endpoint")
	}
	fresh := wirePath{socket, netip.AddrPortFrom(addr, 14500)}
	deliverResponse(fresh)
	if _, ok := b.confirmed[fresh]; ok || len(b.confirmed) != 64 || b.physical != current {
		t.Fatal("new path bypassed capacity or selected route")
	}
}
