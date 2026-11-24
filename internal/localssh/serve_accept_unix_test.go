//go:build darwin || linux

package localssh

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func newLocalFixtureListener(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestLocalSessionAcceptReturnsOnlySelectedSocket(t *testing.T) {
	ln := newLocalFixtureListener(t)
	deadline := time.Now().Add(3 * time.Second)
	connect := func() *net.TCPConn {
		t.Helper()
		d := net.Dialer{Deadline: deadline}
		c, err := d.DialContext(t.Context(), "tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		tcp := c.(*net.TCPConn)
		t.Cleanup(func() { _ = tcp.Close() })
		if err := tcp.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		return tcp
	}
	stale, selected := connect(), connect()
	f, err := acceptLocalSocket(ln, selected.LocalAddr().(*net.TCPAddr).Port, deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if n, err := stale.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("unselected connection was not closed: read %d / %v", n, err)
	}
	// Continue through a net.Conn so the assertion itself has an I/O deadline.
	conn, err := net.FileConn(f)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	const message = "only selected terminal"
	if _, err := selected.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != message {
		t.Fatalf("selected socket did not survive file handoff: %q / %v", buf, err)
	}
}

func TestLocalSessionAcceptHonorsTimeoutAndClosedListener(t *testing.T) {
	ln := newLocalFixtureListener(t)
	if f, err := acceptLocalSocket(ln, 5000, time.Now().Add(-time.Second)); f != nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired attach deadline: %v / %v", f, err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if f, err := acceptLocalSocket(ln, 5000, time.Now().Add(time.Second)); f != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed listener: %v / %v", f, err)
	}
}
