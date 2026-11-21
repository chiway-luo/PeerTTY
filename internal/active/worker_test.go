package active

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"peertty/internal/grant"
)

func TestLocalClientsShareOnlyApprovedPeer(t *testing.T) {
	t.Run("revoke", func(t *testing.T) { exerciseSharedPeer(t, time.Minute) })
	t.Run("expiry", func(t *testing.T) { exerciseSharedPeer(t, 5*time.Second) })
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
	earliestHostDeadline := time.Now().Add(ttl)
	start(Options{Role: "host", Key: host, Port: listener.Addr().(*net.TCPAddr).Port, TTL: ttl})
	a := wait(host, "waiting")
	offer, err := grant.Read(a.Exchange)
	if err != nil {
		t.Fatal(err)
	}
	start(Options{Role: "control", Key: operator, Offer: offer, User: "fixture"})
	b := wait(operator, "waiting")
	if c, err := Pipe(ctx, operator, b.ID); err == nil {
		c.Close()
		t.Fatal("opened before approval")
	}
	// A different device identity cannot even read this worker's status.
	stranger := newKey()
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
	if err = Approve(ctx, host, a.ID, answer); err != nil {
		t.Fatal(err)
	}
	wait(host, "ready")
	wait(operator, "ready")
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
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
}
