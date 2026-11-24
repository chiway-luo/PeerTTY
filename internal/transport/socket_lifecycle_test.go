package transport

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/deadline"
)

type socketLifecycleFixture struct {
	transport.UDPConn
	writeDeadline      time.Time
	writeErr, closeErr error
	writes, closes     int
}

func (c *socketLifecycleFixture) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return c.writeErr
}
func (c *socketLifecycleFixture) Close() error {
	c.closes++
	return c.closeErr
}
func (c *socketLifecycleFixture) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.writes++
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(b), nil
}

func TestSocketReadsOwnedDatagramsAndPreservesBoundedQueue(t *testing.T) {
	owner := &roaming{done: make(chan struct{})}
	s := &roamSocket{owner: owner, done: make(chan struct{}), read: deadline.New(), queue: make(chan roamPacket, 1)}
	packet := []byte("hello")
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	s.deliver(packet, from)
	packet[0] = 'X'
	s.deliver([]byte("overflow"), from)
	got := make([]byte, 16)
	n, addr, err := s.ReadFrom(got)
	if err != nil || n != 5 || string(got[:n]) != "hello" || addr != from || len(s.queue) != 0 {
		t.Fatalf("unexpected queue read %q / %v / %v", got[:n], addr, err)
	}
	s.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := s.ReadFrom(got); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline returned %v", err)
	}
	s.SetReadDeadline(time.Time{})
	close(owner.done)
	if _, _, err := s.ReadFrom(got); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("stopped owner returned %v", err)
	}
}

func TestSocketForwardsDeadlinesAndClosesUnderlyingSocketOnce(t *testing.T) {
	closeErr := errors.New("fixture close")
	stub := &socketLifecycleFixture{closeErr: closeErr}
	s := &roamSocket{UDPConn: stub, owner: &roaming{done: make(chan struct{})}, done: make(chan struct{}), read: deadline.New()}
	d := time.Now().Add(time.Hour)
	if err := s.SetDeadline(d); err != nil || stub.writeDeadline != d {
		t.Fatalf("write deadline not forwarded: %v / %v", stub.writeDeadline, err)
	}
	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	if n, err := s.WriteTo([]byte("abc"), to); n != 3 || err != nil || stub.writes != 1 {
		t.Fatalf("ordinary datagram not forwarded: %d / %v", n, err)
	}
	stub.writeErr = syscall.ENETUNREACH
	if n, err := s.WriteTo([]byte("abc"), to); n != 0 || !errors.Is(err, syscall.ENETUNREACH) || stub.writes != 2 {
		t.Fatalf("unpaired network failure was hidden: %d / %v", n, err)
	}
	if err := s.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("close lost underlying error: %v", err)
	}
	if err := s.Close(); err != nil || stub.closes != 1 {
		t.Fatalf("close called %d times: %v", stub.closes, err)
	}
	if _, _, err := s.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := s.WriteTo(nil, to); !errors.Is(err, net.ErrClosed) || stub.writes != 2 {
		t.Fatalf("write after close: %v", err)
	}
}

func TestRouteUnavailableDistinguishesPathErrorsFromPermanentFailures(t *testing.T) {
	for _, err := range []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EADDRNOTAVAIL,
		syscall.ENETDOWN, syscall.EHOSTDOWN, syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENOBUFS} {
		if !routeUnavailable(&os.SyscallError{Syscall: "sendto", Err: err}) {
			t.Fatalf("%v not classified as route loss", err)
		}
	}
	for _, err := range []error{nil, os.ErrPermission, net.ErrClosed} {
		if routeUnavailable(err) {
			t.Fatalf("non-route failure %v classified as route loss", err)
		}
	}
}

type pumpRead struct {
	payload string
	addr    net.Addr
	err     error
}

type pumpFixture struct {
	transport.UDPConn
	read   <-chan pumpRead
	closed chan struct{}
}

func (p *pumpFixture) ReadFrom(out []byte) (int, net.Addr, error) {
	select {
	case <-p.closed:
		return 0, nil, net.ErrClosed
	case data := <-p.read:
		return copy(out, data.payload), data.addr, data.err
	}
}
func (p *pumpFixture) Close() error {
	close(p.closed)
	return nil
}

func TestSocketPumpContinuesAfterTransientReadAndDeliversOrdinaryDatagram(t *testing.T) {
	fixtures := make(chan pumpRead, 3)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	fixtures <- pumpRead{err: syscall.ENOBUFS}
	fixtures <- pumpRead{payload: "not UDP", addr: &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}}
	fixtures <- pumpRead{payload: "message", addr: remote}
	base := &pumpFixture{read: fixtures, closed: make(chan struct{})}
	r := &roaming{done: make(chan struct{})}
	n := &roamingNet{Net: fixtureBindNet{conn: base}, roam: r}
	raw, err := n.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	out := make([]byte, 32)
	count, source, err := raw.ReadFrom(out)
	if err != nil || string(out[:count]) != "message" || source != remote {
		t.Fatalf("read retry returned %q / %v / %v", out[:count], source, err)
	}
}

func TestSocketSetupReturnsBindFailureWithoutOpeningPump(t *testing.T) {
	want := errors.New("fixture bind failed")
	r := &roamingNet{Net: fixtureBindNet{err: want}}
	if c, err := r.ListenUDP("udp4", nil); c != nil || !errors.Is(err, want) {
		t.Fatalf("bind failure exposed socket: %v / %v", c, err)
	}
}

func TestAuxiliarySocketDisposesOfOrdinaryInputAndStopsWithOwner(t *testing.T) {
	fixtures := make(chan pumpRead)
	base := &pumpFixture{read: fixtures, closed: make(chan struct{})}
	owner := &roaming{done: make(chan struct{})}
	s := owner.socket(base, false)
	defer s.Close()
	if s.queue != nil || s.read != nil {
		t.Fatal("auxiliary socket unexpectedly owns the user-facing read queue")
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case fixtures <- pumpRead{payload: "ordinary test message", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}}:
	case <-timer.C:
		t.Fatal("fixture read never started")
	}
	close(owner.done)
	select {
	case fixtures <- pumpRead{err: net.ErrClosed}:
	case <-timer.C:
		t.Fatal("ordinary input prevented cleanup")
	}
}
