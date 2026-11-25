package transport

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/deadline"
)

// A candidate keeps its ordinary UDP socket. Its reader can also receive the
// same ICE/DTLS datagrams through a validated path on another interface.
type roamingNet struct {
	transport.Net
	roam *roaming
}

func (n *roamingNet) ListenUDP(network string, addr *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := n.Net.ListenUDP(network, addr)
	if err != nil {
		return nil, err
	}
	return n.roam.socket(conn, true), nil
}

type roamPacket struct {
	data []byte
	from *net.UDPAddr
}

type roamSocket struct {
	transport.UDPConn
	owner *roaming
	queue chan roamPacket
	read  *deadline.Deadline
	done  chan struct{}
	once  sync.Once
}

func (r *roaming) socket(conn transport.UDPConn, candidate bool) *roamSocket {
	s := &roamSocket{UDPConn: conn, owner: r, done: make(chan struct{})}
	if candidate {
		s.queue = make(chan roamPacket, 128)
		s.read = deadline.New()
	}
	go s.pump()
	return s
}

func (s *roamSocket) pump() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.UDPConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			case <-s.owner.done:
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
		from, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		if bytes.HasPrefix(buf[:n], []byte(roamMagic)) {
			s.owner.receive(wirePath{s, normalizeAddrPort(from.AddrPort())}, buf[:n])
		} else if s.queue != nil {
			s.deliver(buf[:n], from)
		}
	}
}

func (s *roamSocket) deliver(data []byte, from *net.UDPAddr) {
	p := roamPacket{bytes.Clone(data), from}
	select {
	case s.queue <- p:
	default: // UDP backpressure drops a datagram. ICE/SCTP own retransmission.
	}
}

func (s *roamSocket) ReadFrom(buf []byte) (int, net.Addr, error) {
	select {
	case <-s.done:
		return 0, nil, net.ErrClosed
	case <-s.owner.done:
		return 0, nil, net.ErrClosed
	case <-s.read.Done():
		return 0, nil, os.ErrDeadlineExceeded
	case p := <-s.queue:
		return copy(buf, p.data), p.from, nil
	}
}

func (s *roamSocket) WriteTo(data []byte, dest net.Addr) (int, error) {
	select {
	case <-s.done:
		return 0, net.ErrClosed
	default:
	}
	if udp, ok := dest.(*net.UDPAddr); ok {
		dst := normalizeAddrPort(udp.AddrPort())
		if sent, err := s.owner.write(wirePath{s, dst}, data); sent {
			if err != nil {
				return 0, err
			}
			return len(data), nil
		}
	}
	n, err := writeStartupDatagram(s.UDPConn, data, dest, s.owner.reserveStartupCopy(data, time.Now()))
	if s.owner.keys.Load() != nil && routeUnavailable(err) {
		return len(data), nil
	}
	return n, err
}

// A best-effort startup copy goes to the same ICE-selected peer. Reuse the
// identical wire bytes so the receiving replay filters discard the duplicate.
func writeStartupDatagram(conn transport.UDPConn, data []byte, dest net.Addr, repeat bool) (int, error) {
	n, err := conn.WriteTo(data, dest)
	if err == nil && n == len(data) && repeat {
		_, _ = conn.WriteTo(data, dest)
	}
	return n, err
}

func routeUnavailable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.EHOSTDOWN) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENOBUFS)
}
func (s *roamSocket) SetReadDeadline(t time.Time) error { s.read.Set(t); return nil }

func (s *roamSocket) SetDeadline(t time.Time) error {
	s.read.Set(t)
	return s.UDPConn.SetWriteDeadline(t)
}

func (s *roamSocket) Close() error {
	var err error
	s.once.Do(func() {
		close(s.done)
		if s.read != nil {
			s.read.Set(time.Time{})
		}
		err = s.UDPConn.Close()
	})
	return err
}

// A physical path includes the receiving socket; a response on a different
// socket cannot prove that the challenged NAT mapping is reachable.
type wirePath struct {
	socket *roamSocket
	addr   netip.AddrPort
}

func (p wirePath) send(c *roamCipher, kind byte, payload []byte) error {
	wire := c.seal(kind, payload)
	_, err := p.socket.UDPConn.WriteTo(wire, net.UDPAddrFromAddrPort(p.addr))
	return err
}
