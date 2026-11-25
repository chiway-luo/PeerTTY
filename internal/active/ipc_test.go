package active

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"peertty/internal/grant"
)

func TestStatusCountdownUsesWorkerBudgetAfterWallClockRollback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left := 2 * time.Second
		state := State{Deadline: time.Now().Add(24 * time.Hour).Round(0), Remaining: &left}
		state.startCountdown()
		if got := state.TimeLeft(); got != left {
			t.Fatalf("reported %s for a %s remaining grant", got, left)
		}
		time.Sleep(left)
		if got := state.TimeLeft(); got != 0 {
			t.Fatalf("countdown still shows %s", got)
		}
		legacy := State{Deadline: time.Now().Add(time.Minute).Round(0)}
		if got := legacy.TimeLeft(); got != time.Minute {
			t.Fatalf("old worker countdown: %s", got)
		}
	})
}

func TestLocalFramesStaySeparate(t *testing.T) {
	var stream bytes.Buffer
	first := request{Op: "status", ID: "one"}
	second := request{Op: "revoke", ID: "two"}
	for _, req := range []request{first, second} {
		if err := send(&stream, req); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []request{first, second} {
		var got request
		if err := receive(&stream, &got); err != nil || got != want {
			t.Fatalf("frame: %+v, %v", got, err)
		}
	}
	if err := receive(&stream, &request{}); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end: %v", err)
	}
	if err := send(&stream, strings.Repeat("x", frameLimit)); err == nil || stream.Len() != 0 {
		t.Fatal("oversized frame reached stream")
	}
}

func TestLocalTLSRejectsASeparateClientIdentity(t *testing.T) {
	makeConfig := func() *tls.Config {
		t.Helper()
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := localTLS(key)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	server := makeConfig()
	for _, tc := range []struct {
		name string
		cfg  *tls.Config
		want bool
	}{{"owner", server.Clone(), true}, {"other identity", makeConfig(), false}} {
		t.Run(tc.name, func(t *testing.T) {
			// Both clients trust the real worker. Only the owner may authenticate to it.
			tc.cfg.RootCAs = server.RootCAs
			left, right := net.Pipe()
			defer left.Close()
			deadline := time.Now().Add(3 * time.Second)
			left.SetDeadline(deadline)
			right.SetDeadline(deadline)
			done := make(chan error, 1)
			go func() {
				defer right.Close()
				done <- tls.Server(right, server).HandshakeContext(t.Context())
			}()
			client := tls.Client(left, tc.cfg)
			clientErr := client.HandshakeContext(t.Context())
			_, _ = io.Copy(io.Discard, client)
			err := <-done
			if tc.want {
				if err != nil || clientErr != nil {
					t.Fatalf("owner handshake: client %v, server %v", clientErr, err)
				}
			} else {
				var certErr *tls.CertificateVerificationError
				if err == nil || (!errors.As(err, &certErr) && !strings.Contains(err.Error(), "client didn't provide a certificate")) {
					t.Fatalf("expected server-side certificate refusal, got %v", err)
				}
			}
		})
	}
}

func TestLocalFrameBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    uint32
		payload string
	}{
		{"empty", 0, ""}, {"over limit", frameLimit + 1, ""}, {"truncated", 8, "{}"}, {"invalid JSON", 1, "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := binary.BigEndian.AppendUint32(nil, tc.size)
			if err := receive(bytes.NewReader(append(data, tc.payload...)), &reply{}); err == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
}

func TestRejectedBootstrapLeavesNoActiveGrant(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	for _, opt := range []Options{
		{Role: "other", Key: key},
		{Role: "host", Key: key, Port: 22, TTL: 0},
		{Role: "host", Key: key, Port: 65536, TTL: time.Minute},
		{Role: "control", Key: key},
	} {
		var input, ready bytes.Buffer
		if err := send(&input, opt); err != nil {
			t.Fatal(err)
		}
		if err := Serve(t.Context(), &input, &ready); err == nil || ready.Len() != 0 {
			t.Fatalf("rejected bootstrap %q reported readiness", opt.Role)
		}
		if _, err := Status(t.Context(), key); !errors.Is(err, ErrInactive) {
			t.Fatalf("stale state: %v", err)
		}
	}
	for _, port := range []string{"0", "65536", "unreadable"} {
		if err := os.WriteFile(key+".active", []byte(port), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Status(t.Context(), key); err == nil || errors.Is(err, ErrInactive) {
			t.Fatalf("corrupt rendezvous %q: %v", port, err)
		}
	}
}

func TestConcurrentTerminalLimitAndSlotReuse(t *testing.T) {
	var w worker
	const attempts = 64
	start := make(chan struct{})
	result := make(chan bool, attempts)
	for range attempts {
		go func() {
			<-start
			result <- w.enter()
		}()
	}
	close(start)
	admitted := 0
	for range attempts {
		if <-result {
			admitted++
		}
	}
	if admitted != 32 || w.snapshot().Terminals != admitted {
		t.Fatalf("admitted %d, reported %d", admitted, w.snapshot().Terminals)
	}
	w.leave()
	if !w.enter() {
		t.Fatal("released slot was not reusable")
	}
	w.stopping = true
	for range admitted {
		w.leave()
	}
	w.links.Wait()
	if w.enter() || w.snapshot().Terminals != 0 {
		t.Fatal("stopping worker accepted a new terminal")
	}
}

func TestWorkerAcceptsOneApprovalForTheCurrentGrant(t *testing.T) {
	_, hostKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, clientKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := grant.NewPairingOffer(hostKey, "local offer", "operator", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	answer, err := grant.NewAnswer(clientKey, offer, "local answer")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := localTLS(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixtureCode.Seal(&answer); err != nil {
		t.Fatal(err)
	}
	w := worker{offer: offer, state: State{PairingCode: fixtureCode, ID: "current", Role: "host", Phase: "waiting"}, approval: make(chan grant.Ticket, 1)}
	revoked := false
	callWorker := func(req request) reply {
		t.Helper()
		left, right := net.Pipe()
		defer left.Close()
		if err := left.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			w.handle(t.Context(), tls.Server(right, cfg), func() { revoked = true })
		}()
		client := tls.Client(left, cfg)
		if err := send(client, req); err != nil {
			t.Fatal(err)
		}
		var res reply
		if err := receive(client, &res); err != nil {
			t.Fatal(err)
		}
		left.Close()
		<-done
		return res
	}
	for _, invalid := range []request{
		{Op: "approve", ID: "expired", Answer: &answer},
		{Op: "approve", ID: "current"},
		{Op: "revoke", ID: "expired"},
		{Op: "link", ID: "current"},
		{Op: "unknown", ID: "current"},
	} {
		if res := callWorker(invalid); res.Error == "" || w.snapshot().Phase != "waiting" || revoked {
			t.Fatalf("invalid %q changed the grant", invalid.Op)
		}
	}
	approval := request{Op: "approve", ID: "current", Answer: &answer}
	w.update(func(s *State) { s.RequireScoped = true })
	if res := callWorker(approval); res.Error == "" || w.snapshot().Phase != "waiting" || len(w.approval) != 0 {
		t.Fatal("accepted a system SSH login after only the scoped configuration passed")
	}
	w.update(func(s *State) { s.RequireScoped = false })
	if res := callWorker(approval); res.Error != "" || res.State.Phase != "connecting" {
		t.Fatalf("approval: %+v", res)
	}
	select {
	case got := <-w.approval:
		if !bytes.Equal(got.Signature, answer.Signature) {
			t.Fatal("wrong signed answer delivered")
		}
	default:
		t.Fatal("no approval delivered")
	}
	if res := callWorker(approval); res.Error == "" || len(w.approval) != 0 {
		t.Fatal("duplicate approval accepted")
	}
	_, otherKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := grant.NewAnswer(otherKey, offer, "another controller")
	if err != nil {
		t.Fatal(err)
	}
	w.update(func(s *State) { s.Phase = "ready" })
	if res := callWorker(request{Op: "approve", ID: "current", Answer: &other}); res.Error == "" ||
		w.snapshot().Phase != "ready" || len(w.approval) != 0 {
		t.Fatal("second signed controller receipt changed an active grant")
	}
	// A reconnecting grant must still accept a local revoke without a peer
	// transport. The old grant ID must not be able to stop another grant.
	w.update(func(s *State) { s.Phase = "disconnected" })
	if res := callWorker(request{Op: "revoke", ID: "replaced"}); res.Error == "" || revoked {
		t.Fatal("stale ID revoked the reconnecting grant")
	}
	if res := callWorker(request{Op: "revoke", ID: "current"}); res.Error != "" || !revoked {
		t.Fatal("current grant not revoked", res.Error)
	}
	if w.enter() {
		w.leave()
		t.Fatal("revoking grant still admits terminal streams")
	}
}

type readinessFailure struct {
	path string
	t    *testing.T
	err  error
}

func (f readinessFailure) Write([]byte) (int, error) {
	// Readiness is written only once the rendezvous has been published,
	// so a failing writer exercises cleanup of an already-visible startup.
	if _, err := os.Stat(f.path); err != nil {
		f.t.Errorf("rendezvous was not published before readiness: %v", err)
	}
	return 0, f.err
}

func TestFailedReadinessRemovesRendezvousAndReleasesLease(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "identity")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	opts := Options{Role: "host", Key: key, Port: 22, TTL: time.Minute}
	launch := func(out io.Writer) error {
		t.Helper()
		var input bytes.Buffer
		if err := send(&input, opts); err != nil {
			t.Fatal(err)
		}
		return Serve(t.Context(), &input, out)
	}
	lease, err := grant.LeaseIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	err = launch(io.Discard)
	if closeErr := lease.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(err, grant.ErrInUse) {
		t.Fatalf("concurrent launch: %v", err)
	}

	want := errors.New("readiness receiver gone")
	if err := launch(readinessFailure{key + ".active", t, want}); !errors.Is(err, want) {
		t.Fatalf("startup returned %v, want readiness failure", err)
	}
	if _, err := Status(t.Context(), key); !errors.Is(err, ErrInactive) {
		t.Fatalf("stale rendezvous: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".peertty-port-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary rendezvous files: %v, %v", matches, err)
	}
	lease, err = grant.LeaseIdentity(key)
	if err != nil {
		t.Fatalf("startup leaked identity lease: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStatusDistinguishesUnreadableDiscoveryAndMissingIdentity(t *testing.T) {
	key := filepath.Join(t.TempDir(), "fixture.key")
	if err := os.Mkdir(key+".active", 0700); err != nil {
		t.Fatal(err)
	}
	if s, err := Status(t.Context(), key); err == nil || errors.Is(err, ErrInactive) || s != (State{}) {
		t.Fatalf("directory in place of status returned %+v / %v", s, err)
	}
	if err := os.Remove(key + ".active"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key+".active", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := Status(t.Context(), key); !errors.Is(err, ErrInactive) || s != (State{}) {
		t.Fatalf("missing local identity returned %+v / %v", s, err)
	}
}

func TestStatusReportsCanceledDialWithoutAnActiveGrant(t *testing.T) {
	key := filepath.Join(t.TempDir(), "fixture.key")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key+".active", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if s, err := Status(ctx, key); !errors.Is(err, ErrInactive) || s != (State{}) {
		t.Fatalf("canceled status returned %+v / %v", s, err)
	}
}

func TestCachedLocalTLSBoundsEntriesAndRetainsMatchingIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 33; i++ {
		key := filepath.Join(dir, fmt.Sprintf("fixture-%d.key", i))
		disk := writeTestIPCKey(t, key)
		c, err := cachedLocalTLS(key)
		if err != nil {
			t.Fatalf("load fixture %d: %v", i, err)
		}
		private, ok := c.Certificates[0].PrivateKey.(ed25519.PrivateKey)
		if !ok || !bytes.Equal(private, disk) {
			t.Fatalf("configuration for fixture %d used a different identity", i)
		}
		tlsCacheMu.Lock()
		size := len(tlsCache)
		tlsCacheMu.Unlock()
		if size > 32 {
			t.Fatalf("identity cache retained %d entries", size)
		}
	}
}
