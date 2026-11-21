// Package bridge carries one SSH byte stream over an ordered message channel.
package bridge

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const chunkSize = 16 * 1024

// ProxyDrainTimeout bounds the final FIN/ACK exchange after native SSH exits.
// Under loss both FIN and ACK may need multiple SCTP retransmissions.
const ProxyDrainTimeout = 12 * time.Second

type Channel interface {
	io.Closer
	ReadDataChannel([]byte) (int, bool, error)
	WriteDataChannel([]byte, bool) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type Endpoint interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// Run owns local. The caller owns the peer connection and closes it on return.
// Binary messages carry bytes; ordered text FIN/ACK records preserve TCP half-close.
func Run(ctx context.Context, wire Channel, local Endpoint) error {
	defer local.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	var lock sync.Mutex
	send := func(data []byte, control bool) error {
		lock.Lock()
		defer lock.Unlock()
		n, err := wire.WriteDataChannel(data, control)
		if err == nil && n != len(data) {
			return io.ErrShortWrite
		}
		return err
	}
	var sentFIN atomic.Bool
	results := make(chan error, 2)
	go func() {
		buf := make([]byte, chunkSize)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				if e := send(buf[:n], false); e != nil {
					results <- e
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					sentFIN.Store(true)
					err = send([]byte("FIN"), true)
				}
				results <- err
				return
			}
		}
	}()
	go func() { results <- receive(wire, local, send, &sentFIN) }()
	defer func() {
		// Release in-flight SCTP operations on cancellation, even during backpressure.
		now := time.Now()
		_ = wire.SetReadDeadline(now)
		_ = wire.SetWriteDeadline(now)
	}()
	for range 2 {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case err := <-results:
			if err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func receive(wire Channel, local Endpoint, send func([]byte, bool) error, sentFIN *atomic.Bool) error {
	buf := make([]byte, chunkSize)
	var fin, ack bool
	for !fin || !ack {
		n, control, err := wire.ReadDataChannel(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if !control {
			if fin {
				return errors.New("received bytes after FIN")
			}
			written, err := local.Write(buf[:n])
			if err != nil {
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
			continue
		}
		switch string(buf[:n]) {
		case "FIN":
			if fin {
				return errors.New("duplicate FIN")
			}
			fin = true
			if err := local.CloseWrite(); err != nil {
				return err
			}
			if err := send([]byte("ACK"), true); err != nil {
				return err
			}
		case "ACK":
			if ack || !sentFIN.Load() {
				return errors.New("unexpected FIN acknowledgement")
			}
			ack = true
		default:
			return errors.New("unknown stream control record")
		}
	}
	// FIN and its ACK cover application bytes in both directions. Let SCTP
	// exchange stream resets before the owner tears down the whole association,
	// otherwise its abort can overtake our last ACK on the other peer.
	if err := wire.Close(); err == nil {
		if _, _, err := wire.ReadDataChannel(buf); err == nil {
			return errors.New("unexpected record after stream shutdown")
		}
	}
	return nil
}
