package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestPeerChannelSurfacesLocalSetupFailureOrCancellation(t *testing.T) {
	for _, tc := range []struct {
		name                string
		readyErr, parentErr error
		want                string
	}{
		{"stream failed", errors.New("fixture data stream failure"), nil, ""},
		{"ready without selected route", nil, nil, "no selected ICE candidate pair"},
		{"lifetime ended", nil, errors.New("fixture stopped"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			p, err := New(parent, "none")
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if tc.parentErr != nil {
				cancel(tc.parentErr)
			} else {
				p.ready <- opened{err: tc.readyErr}
			}
			channel, route, err := p.Channel(t.Context())
			if channel != nil || route != "" || err == nil {
				t.Fatalf("setup failure returned a route: %v / %q / %v", channel, route, err)
			}
			if (tc.readyErr != nil && !errors.Is(err, tc.readyErr)) ||
				(tc.parentErr != nil && !errors.Is(err, tc.parentErr)) ||
				(tc.want != "" && !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("setup failure was obscured: %v", err)
			}
		})
	}
}

func TestSingleSessionDoesNotEnableMigrationAndRejectsRequestsAfterClose(t *testing.T) {
	p, err := New(t.Context(), "none")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.BindGrant(nil); err != nil || p.CanRoam() || p.Migrated() {
		t.Fatalf("single-session peer advertised migration: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(context.Cause(p.Context()), context.Canceled) || p.Connected() {
		t.Fatal("closed peer still active")
	}
	if _, err := p.OpenLink(t.Context()); err == nil {
		t.Fatal("closed peer opened another terminal")
	}
	if _, err := p.Offer(t.Context()); err == nil {
		t.Fatal("closed peer produced another offer")
	}
	if _, err := p.gather(t.Context(), webrtc.SessionDescription{Type: webrtc.SDPTypeOffer}); err == nil {
		t.Fatal("closed peer accepted a new local description")
	}
}

func TestRemoteSTUNDetectionDoesNotResolveHosts(t *testing.T) {
	if hasRemoteSTUN([]string{"not a URI", "stun:LOCALHOST:3478", "stun:[::1]:3478"}) {
		t.Fatal("loopback-only STUN was treated as remote")
	}
	for _, u := range []string{"stun:example.test:3478", "stun:192.0.2.1:3478"} {
		if !hasRemoteSTUN([]string{u}) {
			t.Fatalf("configured remote endpoint not recognized: %q", u)
		}
	}
}

func TestOpenLinkCancellationKeepsGrantUsableAndReportsLifetimeCause(t *testing.T) {
	parent, end := context.WithCancelCause(t.Context())
	defer end(nil)
	p, err := New(parent, "none")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if stream, err := p.OpenLink(ctx); stream != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled terminal setup: stream=%v err=%v", stream, err)
	}
	if p.Context().Err() != nil {
		t.Fatal("canceling an individual terminal ended the grant")
	}
	if stream, route, err := p.Channel(ctx); stream != nil || route != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled channel wait: stream=%v route=%q err=%v", stream, route, err)
	}
	reason := errors.New("fixture grant ended")
	end(reason)
	guard, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if stream, err := p.OpenLink(guard); stream != nil || !errors.Is(err, reason) {
		t.Fatalf("expired grant lost end cause: stream=%v err=%v", stream, err)
	}
}

func TestReusablePeerMigrationLifecycle(t *testing.T) {
	p, err := NewGrant(t.Context(), "none")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	other, err := newRoaming(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer other.close()
	key := base64.RawStdEncoding.EncodeToString(other.key.PublicKey().Bytes())
	p.roam.setRemote(key, true, nil)
	if p.CanRoam() || p.Migrated() {
		t.Fatal("unbound grant claimed roaming or a migrated route")
	}
	if err := p.BindGrant(nil); err == nil || p.CanRoam() {
		t.Fatalf("missing approved receipt enabled migration: %v", err)
	}
	_, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt := ed25519.Sign(signer, []byte("test-local approved receipt"))
	if err := p.BindGrant(receipt); err != nil || !p.CanRoam() || p.Migrated() {
		t.Fatalf("signed grant did not enable migration separately from path selection: %v", err)
	}
	if err := p.BindGrant(receipt); err == nil {
		t.Fatal("binding the grant twice reset the route state")
	}
	p.roam.mu.Lock()
	p.roam.physical = wirePath{&roamSocket{UDPConn: &socketLifecycleFixture{}}, netip.MustParseAddrPort("127.0.0.1:5000")}
	p.roam.lastProof = time.Now()
	p.roam.mu.Unlock()
	if !p.Migrated() {
		t.Fatal("validated physical path was not reflected in status")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.roam.done:
	default:
		t.Fatal("peer shutdown left route recovery open")
	}
}
