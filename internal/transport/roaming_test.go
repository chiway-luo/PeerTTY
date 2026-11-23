package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"
)

func roamingPair(t *testing.T, ctx context.Context) (*roaming, *roaming) {
	t.Helper()
	a, err := newRoaming(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newRoaming(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := func(r *roaming) string { return base64.RawStdEncoding.EncodeToString(r.key.PublicKey().Bytes()) }
	signature := make([]byte, 64)
	rand.Read(signature)
	out, err := newRoamCipher(a.key, key(b), signature, true)
	if err != nil {
		t.Fatal(err)
	}
	in, err := newRoamCipher(b.key, key(a), signature, false)
	if err != nil {
		t.Fatal(err)
	}
	a.keys.Store(out)
	b.keys.Store(in)
	return a, b
}

func TestRoamingBindsKeysDirectionAndGrant(t *testing.T) {
	a, b := roamingPair(t, t.Context())
	_, other := roamingPair(t, t.Context())
	data := []byte("ICE datagram")
	wire := a.keys.Load().seal(pathData, data)
	for _, receiver := range []*roaming{a, other} {
		if _, _, ok := receiver.keys.Load().open(bytes.Clone(wire)); ok {
			t.Fatal("accepted reflected frame or another grant's key")
		}
	}
	corrupt := bytes.Clone(wire)
	corrupt[len(corrupt)-1] ^= 1
	if _, _, ok := b.keys.Load().open(corrupt); ok {
		t.Fatal("accepted modified frame")
	}
	wrongReceipt, err := newRoamCipher(b.key, base64.RawStdEncoding.EncodeToString(a.key.PublicKey().Bytes()), make([]byte, 64), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := wrongReceipt.open(bytes.Clone(wire)); ok {
		t.Fatal("accepted the same peer keys with a different signed receipt")
	}
	next := a.keys.Load().seal(pathData, data)
	if _, _, ok := b.keys.Load().open(next); !ok {
		t.Fatal("new packet rejected")
	}
	kind, body, ok := b.keys.Load().open(bytes.Clone(wire))
	if !ok || kind != pathData || !bytes.Equal(body, data) {
		t.Fatal("paired endpoint failed to open the frame")
	}
	if _, _, ok := b.keys.Load().open(wire); ok {
		t.Fatal("accepted repeated frame")
	}
}

func TestRoamingRequiresReturnPathAndHonorsRevocation(t *testing.T) {
	ctx, revoke := context.WithCancel(t.Context())
	defer revoke()
	a, b := roamingPair(t, ctx)
	ice := &roamSocket{queue: make(chan roamPacket, 2)}
	b.logical = wirePath{ice, netip.MustParseAddrPort("192.0.2.3:5123")}
	physical := wirePath{&roamSocket{}, netip.MustParseAddrPort("198.51.100.4:6281")}
	otherSocket := wirePath{&roamSocket{}, physical.addr}
	otherSource := wirePath{physical.socket, netip.MustParseAddrPort("198.51.100.4:6282")}
	ch := routeChallenge{issued: time.Now()}
	rand.Read(ch.token[:])
	b.challenges[physical] = ch
	reply := func(path wirePath) { b.receive(path, a.keys.Load().seal(pathResponse, ch.token[:])) }
	for _, path := range []wirePath{otherSocket, otherSource} {
		reply(path)
	}
	b.receive(physical, a.keys.Load().seal(pathResponse, make([]byte, 16)))
	ch.issued = time.Now().Add(-2 * pathLifetime)
	b.challenges[physical] = ch
	reply(physical)
	if b.physical.socket != nil {
		t.Fatal("accepted a different tuple, incorrect nonce or expired proof")
	}
	ch.issued = time.Now()
	b.challenges[physical] = ch
	reply(physical)
	if b.physical != physical {
		t.Fatal("valid path rejected")
	}
	wire := a.keys.Load().seal(pathData, []byte("data"))
	b.receive(physical, bytes.Clone(wire))
	b.receive(physical, wire)
	b.receive(otherSource, a.keys.Load().seal(pathData, []byte("unproved")))
	if len(ice.queue) != 1 {
		t.Fatal("accepted replay or data from an unproved source")
	}
	p := <-ice.queue
	if p.from.AddrPort() != b.logical.addr || string(p.data) != "data" {
		t.Fatalf("ICE received the wrong logical source or payload: %+v", p)
	}
	// A one-way path can still deliver data. Only an echoed fresh challenge
	// establishes that our outgoing traffic reaches the peer after it moves.
	oldProof := time.Now().Add(-pathLifetime)
	b.confirmed[physical], b.lastProof = oldProof, oldProof
	b.receive(physical, a.keys.Load().seal(pathData, []byte("one way")))
	<-ice.queue
	if b.confirmed[physical] != oldProof || b.lastProof != oldProof {
		t.Fatal("incoming data refreshed outgoing path consent")
	}
	candidate := wirePath{physical.socket, netip.MustParseAddrPort("203.0.113.4:6282")}
	b.challenges[candidate] = ch
	reply(candidate)
	if b.physical != candidate {
		t.Fatal("fresh round trip did not replace the one-way path")
	}
	revoke()
	b.challenges[otherSource] = ch
	reply(otherSource)
	if _, ok := b.confirmed[otherSource]; ok {
		t.Fatal("authorized a new path after revocation")
	}
	b.close()
	b.receive(physical, a.keys.Load().seal(pathData, []byte("closed")))
	if len(ice.queue) != 0 {
		t.Fatal("closed transport accepted a datagram")
	}
}

func TestGrantNegotiatesOrdinaryICEWithOlderPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("opens two direct WebRTC peers")
	}
	for _, direction := range []string{"offer", "answer"} {
		t.Run(direction, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			modern, err := NewGrant(ctx, "none")
			if err != nil {
				t.Fatal(err)
			}
			defer modern.Close()
			legacy, err := New(ctx, "none")
			if err != nil {
				t.Fatal(err)
			}
			defer legacy.Close()
			host, control := modern, legacy
			if direction == "answer" {
				host, control = legacy, modern
			}
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
			if err = modern.BindGrant(make([]byte, 64)); err != nil {
				t.Fatal(err)
			}
			for _, p := range []*Peer{host, control} {
				if _, _, err = p.Channel(ctx); err != nil || p.CanRoam() {
					t.Fatalf("mixed-version connection: roaming=%v, err=%v", p.CanRoam(), err)
				}
			}
		})
	}
}
