package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"peertty/internal/grant"
)

// TCP pairs exercise half-close exactly as an SSH process attached to a ProxyCommand.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a.(*net.TCPConn), b.(*net.TCPConn)
}

type notifier struct {
	once  sync.Once
	wrote chan struct{}
}

func (n *notifier) Write(b []byte) (int, error) {
	n.once.Do(func() { close(n.wrote) })
	return len(b), nil
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case item := <-ch:
		return item
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for session event")
		var zero T
		return zero
	}
}

type active struct {
	app, backend *net.TCPConn
	host, client chan error
	stopClient   context.CancelFunc
}

func startPair(t *testing.T, ttl time.Duration) active {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hostPub, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	opPub, opKey, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	offer, answer := filepath.Join(dir, "session.offer"), filepath.Join(dir, "session.answer")
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	offerReady, approve := make(chan struct{}), make(chan struct{})
	written := &notifier{wrote: make(chan struct{})}
	hostDone, clientDone := make(chan error, 1), make(chan error, 1)
	go func() {
		hostDone <- Host(ctx, HostOptions{
			Options: Options{Key: hostKey, Peer: grant.Fingerprint(opPub), OfferPath: offer, Status: io.Discard},
			TTL:     ttl, SSHPort: l.Addr().(*net.TCPAddr).Port,
			Approval: func(ctx context.Context) (string, error) {
				close(offerReady)
				select {
				case <-approve:
					return answer, nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			},
		})
	}()
	await(t, offerReady)
	app, endpoint := tcpPair(t)
	clientCtx, stopClient := context.WithCancel(ctx)
	t.Cleanup(stopClient)
	go func() {
		clientDone <- Connect(clientCtx, Options{Key: opKey, Peer: grant.Fingerprint(hostPub), OfferPath: offer, Status: written}, answer, endpoint)
	}()
	await(t, written.wrote)
	l.SetDeadline(time.Now().Add(25 * time.Millisecond))
	if premature, err := l.AcceptTCP(); err == nil {
		premature.Close()
		t.Fatal("backend contacted before local approval")
	}
	l.SetDeadline(time.Now().Add(8 * time.Second))
	close(approve)
	backend, err := l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	return active{app, backend, hostDone, clientDone, stopClient}
}

func TestOperatorDisconnectReleasesSSH(t *testing.T) {
	s := startPair(t, time.Minute)
	s.stopClient()
	s.backend.SetReadDeadline(time.Now().Add(9 * time.Second))
	if _, err := s.backend.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("SSH service still open after operator disconnect: %v", err)
	}
	await(t, s.host)
	await(t, s.client)
}

func TestDirectSessionHalfClose(t *testing.T) {
	s := startPair(t, 25*time.Second)
	payload := bytes.Repeat([]byte("SSH\x00\xff\r\n"), 90_000)
	reply := append([]byte("received\n"), payload...)
	server := make(chan error, 1)
	go func() {
		in, err := io.ReadAll(s.backend)
		if err == nil && !bytes.Equal(in, payload) {
			err = fmt.Errorf("upstream bytes changed: %d", len(in))
		}
		if err == nil {
			_, err = s.backend.Write(reply)
		}
		if err == nil {
			err = s.backend.CloseWrite()
		}
		server <- err
	}()
	s.app.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := s.app.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := s.app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(s.app)
	if err != nil || !bytes.Equal(out, reply) {
		t.Fatalf("downstream bytes changed: %d, %v", len(out), err)
	}
	if err := await(t, server); err != nil {
		t.Fatal(err)
	}
	for _, done := range []chan error{s.host, s.client} {
		if err := await(t, done); err != nil {
			t.Fatal(err)
		}
	}
}

func TestActiveGrantExpires(t *testing.T) {
	s := startPair(t, 2*time.Second)
	s.backend.SetReadDeadline(time.Now().Add(6 * time.Second))
	if _, err := s.backend.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("backend did not close on expiry: %v", err)
	}
	host, client := await(t, s.host), await(t, s.client)
	if !errors.Is(host, context.DeadlineExceeded) && !errors.Is(client, context.DeadlineExceeded) {
		t.Fatalf("missing deadline, host=%v client=%v", host, client)
	}
}
