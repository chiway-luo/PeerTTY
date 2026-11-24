package active

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"peertty/internal/identitystate"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"peertty/internal/grant"
)

func TestEstablishedGrantBoundsConsecutiveRouteLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var online atomic.Bool
		online.Store(true)
		w := &worker{}
		w.resetLinks(t.Context())
		first := w.linkCtx
		remote := make(chan error, 1)
		done := make(chan error, 1)
		go func() {
			done <- waitForGrantEnd(t.Context(), t.Context(), online.Load, remote, func() { w.resetLinks(t.Context()) })
		}()
		time.Sleep(time.Hour)
		online.Store(false)
		time.Sleep(10 * time.Second)
		online.Store(true)
		time.Sleep(2 * time.Second)
		online.Store(false)
		time.Sleep(10 * time.Second)
		if first.Err() != nil {
			t.Fatal("recovered outage counted against next outage")
		}
		time.Sleep(routeRecoveryWindow - 10*time.Second + 2*time.Second)
		synctest.Wait()
		if first.Err() == nil || w.linkCtx.Err() != nil {
			t.Fatal("stalled SSH window was not released independently of the grant")
		}
		next := w.linkCtx
		time.Sleep(time.Minute)
		online.Store(true)
		time.Sleep(2 * time.Second)
		if next.Err() != nil {
			t.Fatal("a recovered grant lost the lifetime for its new streams")
		}
		remote <- nil
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestProlongedOutageUpdatesAndClearsNotice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var online atomic.Bool
		online.Store(true)
		var warned atomic.Bool
		remote := make(chan error, 1)
		done := make(chan error, 1)
		go func() {
			done <- waitForGrantEndWithNotice(t.Context(), t.Context(), online.Load, remote, func() {}, func(p bool) {
				warned.Store(p)
			})
		}()
		online.Store(false)
		time.Sleep(prolongedOutageWindow + 2*time.Second)
		synctest.Wait()
		if !warned.Load() {
			t.Fatal("expected prolonged outage notice after 60s")
		}
		online.Store(true)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if warned.Load() {
			t.Fatal("prolonged outage notice did not clear on recovery")
		}
		remote <- nil
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestCachedLocalTLSAndLastError(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "device.key")
	writeTestIPCKey(t, keyPath)
	c1, err := cachedLocalTLS(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := cachedLocalTLS(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c1.Certificates[0].Certificate[0], c2.Certificates[0].Certificate[0]) {
		t.Fatal("expected cached certificate reuse for unchanged key")
	}
	// Replace key on disk and confirm cache invalidates immediately.
	writeTestIPCKey(t, keyPath)
	c3, err := cachedLocalTLS(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1.Certificates[0].Certificate[0], c3.Certificates[0].Certificate[0]) {
		t.Fatal("cache did not invalidate after key replacement")
	}

	if _, _, ok := LastError(keyPath); ok {
		t.Fatal("unexpected last error before write")
	}
	writeLastError(keyPath, "STUN 探测超时")
	reason, at, ok := LastError(keyPath)
	if !ok || reason != "STUN 探测超时" || at.IsZero() {
		t.Fatalf("LastError = (%q, %v, %v)", reason, at, ok)
	}
	clearLastError(keyPath)
	if _, _, ok := LastError(keyPath); ok {
		t.Fatal("clearLastError did not remove record")
	}
	// Stale (>15m) or malformed error records are ignored.
	stale := `{"error":"old","at":"` + time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(keyPath+".last-error", []byte(stale), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := LastError(keyPath); ok {
		t.Fatal("stale last error was returned")
	}
	if LogPath("relative.key") != "" || lastErrorPath("relative.key") != "" {
		t.Fatal("relative key path produced a log path")
	}
	// Worker log opens cleanly and truncates when exceeding maxWorkerLogSize.
	logPath := LogPath(keyPath)
	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, bytes.Repeat([]byte("x"), maxWorkerLogSize+100), 0600); err != nil {
		t.Fatal(err)
	}
	f := openWorkerLog(keyPath)
	if f == nil {
		t.Fatal("openWorkerLog returned nil")
	}
	_, _ = f.WriteString("fresh line\n")
	_ = f.Close()
	data, err := os.ReadFile(logPath)
	if err != nil || string(data) != "fresh line\n" {
		t.Fatalf("expected truncated log, got len=%d err=%v", len(data), err)
	}
}

func TestLocalClientsShareOnlyApprovedPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("exercises an active host and controller over local sockets")
	}
	t.Run("revoke", func(t *testing.T) { exerciseSharedPeer(t, time.Minute) })
	t.Run("expiry", func(t *testing.T) { exerciseSharedPeer(t, 5*time.Second) })
}

func TestRevokePendingHostRemovesInvitationAndReleasesIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	key := filepath.Join(t.TempDir(), "device.key")
	if _, err := grant.NewIdentity(key); err != nil {
		cancel()
		t.Fatal(err)
	}
	var bootstrap bytes.Buffer
	if err := send(&bootstrap, Options{Role: "host", Key: key, Port: 2222, TTL: time.Minute, STUN: "none"}); err != nil {
		cancel()
		t.Fatal(err)
	}
	ready, announce := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := Serve(ctx, &bootstrap, announce)
		announce.CloseWithError(err)
		done <- err
	}()
	t.Cleanup(func() {
		cancel()
		ready.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("pending worker did not exit")
		}
	})
	var started reply
	if err := receive(ready, &started); err != nil {
		t.Fatal(err)
	}
	var st State
	for {
		var err error
		st, err = Status(ctx, key)
		if err != nil || st.ID != started.State.ID {
			t.Fatalf("unexpected worker: %v", err)
		}
		if st.Phase == "waiting" {
			break
		}
		if st.Phase != "gathering" || ctx.Err() != nil {
			t.Fatalf("pending host: %s %s", st.Phase, st.Note)
		}
		time.Sleep(10 * time.Millisecond)
	}
	ticket, err := grant.Read(st.Exchange)
	if err != nil || !ticket.Reusable() || st.Terminals != 0 {
		t.Fatal("pending host published an invalid invitation", err)
	}
	if lease, err := grant.LeaseIdentity(key); !errors.Is(err, grant.ErrInUse) {
		if lease != nil {
			lease.Close()
		}
		t.Fatalf("pending grant failed to hold the identity: %v", err)
	}
	if err := Revoke(ctx, key, st.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st.Exchange); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked invitation remains: %v", err)
	}
	if _, err := Status(ctx, key); !errors.Is(err, ErrInactive) {
		t.Fatal("revoked grant remains active", err)
	}
	lease, err := grant.LeaseIdentity(key)
	if err != nil {
		t.Fatal("revocation retained identity", err)
	}
	lease.Close()
}

func exerciseSharedPeer(t *testing.T, ttl time.Duration) {
	ctx, stop := context.WithTimeout(t.Context(), 35*time.Second)
	defer stop()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	newKey := func() string {
		path := filepath.Join(t.TempDir(), "device.key")
		if _, err := grant.NewIdentity(path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	start := func(opts Options) {
		var input bytes.Buffer
		if err := send(&input, opts); err != nil {
			t.Fatal(err)
		}
		c, close := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- Serve(c, &input, io.Discard) }()
		t.Cleanup(func() {
			close()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("serve: %v", err)
				}
			case <-time.After(4 * time.Second):
				t.Error("worker did not stop")
			}
		})
	}
	wait := func(path, phase string) State {
		t.Helper()
		limit := time.Now().Add(11 * time.Second)
		var last State
		for time.Now().Before(limit) {
			s, err := Status(ctx, path)
			if err == nil {
				last = s
				if s.Phase == phase {
					return s
				}
				if s.Phase == "offline" {
					t.Fatalf("worker %s: %s", s.Role, s.Note)
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("want %s, last phase=%s note=%s", phase, last.Phase, last.Note)
		return State{}
	}
	host, operator := newKey(), newKey()
	imageKey, err := os.ReadFile(host)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(operator, imageKey, 0600); err != nil {
		t.Fatal(err)
	}
	earliestHostDeadline := time.Now().Add(ttl)
	start(Options{Role: "host", Key: host, Port: listener.Addr().(*net.TCPAddr).Port, TTL: ttl})
	a := wait(host, "waiting")
	offer, err := grant.Read(a.Exchange)
	if err != nil {
		t.Fatal(err)
	}
	controlOpts := Options{Role: "control", Key: operator, Offer: offer, PairingCode: a.PairingCode, User: "fixture"}
	t.Setenv("PEERTTY_ACTIVE_MAIN_FIXTURE", "1")
	controller, err := Start(ctx, controlOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if st, err := Status(cleanup, operator); err == nil && st.ID == controller.ID {
			_ = Revoke(cleanup, operator, st.ID)
		}
	})
	b := wait(operator, "waiting")
	hostFP := grant.Fingerprint(offer.Claims.Issuer)
	if got := grant.LookupPeer(operator, hostFP, offer.Claims.DeviceName); got.Trust != grant.PeerNew {
		t.Fatal("unapproved offer was recorded as trusted", got)
	}
	if c, err := Pipe(ctx, operator, b.ID); err == nil {
		c.Close()
		t.Fatal("opened before approval")
	}
	// A different device identity cannot even read this worker's status.
	stranger := newKey()
	if err := os.WriteFile(stranger, imageKey, 0600); err != nil {
		t.Fatal(err)
	}
	port, err := os.ReadFile(operator + ".active")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(stranger+".active", port, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Status(ctx, stranger); err == nil {
		t.Fatal("accepted wrong local certificate")
	}
	answer, err := grant.Read(b.Exchange)
	if err != nil {
		t.Fatal(err)
	}
	if offer.Claims.DeviceName == "" || offer.Claims.DeviceName != answer.Claims.DeviceName ||
		bytes.Equal(offer.Claims.Issuer, answer.Claims.Issuer) {
		t.Fatal("expected the same host name and cloned profile with two distinct session signers")
	}
	if err = Approve(ctx, host, a.ID, answer); err != nil {
		t.Fatal(err)
	}
	wait(host, "ready")
	wait(operator, "ready")
	if grant.LookupPeer(operator, hostFP, offer.Claims.DeviceName).Trust != grant.PeerNew ||
		grant.LookupPeer(host, grant.Fingerprint(answer.Claims.Issuer), answer.Claims.DeviceName).Trust != grant.PeerNew {
		t.Fatal("a one-time grant persisted peer trust")
	}
	var terminals []net.Conn
	for i := 0; i < 2; i++ {
		c, err := Pipe(ctx, operator, b.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		terminals = append(terminals, c)
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = c.Write([]byte("echo")); err != nil {
			t.Fatal(err)
		}
		var buf [4]byte
		_, err = io.ReadFull(c, buf[:])
		if err != nil || string(buf[:]) != "echo" {
			hs, e1 := Status(ctx, host)
			cs, e2 := Status(ctx, operator)
			t.Fatalf("stream %d: %v; host=%s/%s %v, control=%s/%s %v", i, err, hs.Phase, hs.Note, e1, cs.Phase, cs.Note, e2)
		}
	}
	if st, err := Status(ctx, host); err != nil || st.Terminals != 2 {
		t.Fatalf("terminal count %d: %v", st.Terminals, err)
	}
	if ttl < time.Minute {
		until := time.Now().Add(ttl + 3*time.Second)
		for time.Now().Before(until) {
			_, e := Status(ctx, host)
			if errors.Is(e, ErrInactive) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if now := time.Now(); now.Before(offer.Deadline()) && now.Before(earliestHostDeadline) {
			t.Fatal("active grant ended before its deadline")
		}
	} else if err = Revoke(ctx, host, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = Status(ctx, host); !errors.Is(err, ErrInactive) {
		t.Fatalf("worker survived grant end: %v", err)
	}
	for i, c := range terminals {
		if err := c.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var buf [1]byte
		n, err := c.Read(buf[:])
		var netErr net.Error
		if n != 0 || err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
			t.Fatalf("terminal %d did not disconnect at grant end: n=%d err=%v", i+1, n, err)
		}
	}
	if c, err := Pipe(ctx, operator, b.ID); err == nil {
		c.Close()
		t.Fatal("ended grant accepted a new terminal")
	}
	if err := WaitEnded(ctx, operator, b.ID); err != nil {
		t.Fatal(err)
	}
	// Start runs a new OS process with the same profile and the original code.
	// The revoked invitation is still within its signed wall-clock lifetime.
	if ttl >= time.Minute {
		if _, err := Start(ctx, controlOpts); !errors.Is(err, grant.ErrOfferUsed) {
			t.Fatalf("fresh controller process accepted the previous grant: %v", err)
		}
	}
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
}

const fixtureCode grant.PairingCode = "00000000-11111111-22222222-33333333"

func writeTestIPCKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := identitystate.Replace(path, key.Seed()); err != nil {
		t.Fatal(err)
	}
	return key
}
