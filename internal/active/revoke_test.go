package active

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"peertty/internal/grant"
)

// Exercise the local client and worker against a disconnected grant, without
// SSH, WebRTC, or a second device. Revocation must not rely on the peer.
func TestRevokeReconnectingWorkerThroughLocalIPC(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")
	if _, err := grant.NewIdentity(keyPath); err != nil {
		t.Fatal(err)
	}
	key, err := grant.LoadIdentity(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := grant.LeaseIdentity(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	cfg, err := localTLS(key)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err := os.WriteFile(keyPath+".active", []byte(fmt.Sprint(socket.Addr().(*net.TCPAddr).Port)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	id := "same-grant"
	w := worker{state: State{ID: id, Role: "control", Phase: "disconnected", Deadline: time.Now().Add(time.Hour)}}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		stop := context.AfterFunc(ctx, func() { socket.Close() })
		defer stop()
		for {
			c, err := socket.Accept()
			if err != nil {
				break
			}
			w.handle(ctx, tls.Server(c, cfg), cancel)
		}
		_ = os.Remove(keyPath + ".active")
		_ = lease.Close()
	}()
	defer func() { cancel(); <-stopped }()
	if s, err := Status(ctx, keyPath); err != nil || s.Phase != "disconnected" {
		t.Fatalf("initial status: %+v, %v", s, err)
	}
	if err := Revoke(ctx, keyPath, "stale-grant"); err == nil {
		t.Fatal("stale grant was accepted")
	}
	if c, err := Pipe(ctx, keyPath, id); err == nil {
		c.Close()
		t.Fatal("disconnected grant opened a stream")
	}
	if err := Approve(ctx, keyPath, id, grant.Ticket{}); err == nil {
		t.Fatal("controller was allowed to approve")
	}
	if err := Revoke(t.Context(), keyPath, id); err != nil {
		t.Fatal(err)
	}
	if _, err := Status(t.Context(), keyPath); !errors.Is(err, ErrInactive) {
		t.Fatalf("revoked grant is still visible: %v", err)
	}
	if c, err := Pipe(t.Context(), keyPath, id); !errors.Is(err, ErrInactive) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("revoke did not prevent subsequent reconnect: %v", err)
	}
}
