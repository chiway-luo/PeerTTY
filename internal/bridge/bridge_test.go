package bridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type record struct {
	data    string
	control bool
}

type memoryChannel struct {
	in, out              chan record
	reading, interrupted chan struct{}
	readOnce, stopOnce   sync.Once
	closed               bool
}

func newMemoryChannel() *memoryChannel {
	return &memoryChannel{in: make(chan record, 8), out: make(chan record, 8), reading: make(chan struct{}), interrupted: make(chan struct{})}
}

func (c *memoryChannel) ReadDataChannel(p []byte) (int, bool, error) {
	c.readOnce.Do(func() { close(c.reading) })
	select {
	case f, ok := <-c.in:
		if !ok {
			return 0, false, io.EOF
		}
		return copy(p, f.data), f.control, nil
	case <-c.interrupted:
		return 0, false, io.ErrClosedPipe
	}
}
func (c *memoryChannel) WriteDataChannel(p []byte, control bool) (int, error) {
	select {
	case c.out <- record{string(p), control}:
		return len(p), nil
	case <-c.interrupted:
		return 0, io.ErrClosedPipe
	}
}
func (c *memoryChannel) SetReadDeadline(time.Time) error {
	c.stopOnce.Do(func() { close(c.interrupted) })
	return nil
}
func (c *memoryChannel) SetWriteDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *memoryChannel) Close() error                       { c.closed = true; return nil }

type memoryEndpoint struct {
	io.ReadCloser
	bytes.Buffer
	halfClosed bool
}

func (e *memoryEndpoint) Read(p []byte) (int, error) { return e.ReadCloser.Read(p) }
func (e *memoryEndpoint) CloseWrite() error          { e.halfClosed = true; return nil }

type shortChannel struct{ *memoryChannel }

func (c shortChannel) WriteDataChannel(p []byte, control bool) (int, error) {
	return len(p) - 1, nil
}

type shortEndpoint struct{ *memoryEndpoint }

func (e shortEndpoint) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestShortWriteFailsTheTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	wire := newMemoryChannel()
	end := &memoryEndpoint{ReadCloser: io.NopCloser(bytes.NewReader([]byte("payload")))}
	if err := Run(ctx, shortChannel{wire}, end); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short network write: %v", err)
	}
	wire = newMemoryChannel()
	wire.in <- record{data: "reply"}
	if err := receive(ctx, wire, shortEndpoint{end}, nil, new(atomic.Bool)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short local write: %v", err)
	}
}

func TestEndedGrantDropsQueuedSSHData(t *testing.T) {
	ctx, stop := context.WithCancelCause(t.Context())
	wire := newMemoryChannel()
	wire.in <- record{data: "queued SSH data"}
	close(wire.in)
	stop(context.DeadlineExceeded)
	end := &memoryEndpoint{}
	if err := receive(ctx, wire, end, nil, new(atomic.Bool)); !errors.Is(err, context.DeadlineExceeded) || end.Len() != 0 {
		t.Fatalf("expired receive: %v, delivered %d bytes", err, end.Len())
	}
}

func TestRunTransfersBinaryAndFinishesBothDirections(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	wire := newMemoryChannel()
	payload := bytes.Repeat([]byte{0, 255, 13, 10}, chunkSize/4+1)
	end := &memoryEndpoint{ReadCloser: io.NopCloser(bytes.NewReader(payload))}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, wire, end) }()
	next := func() record {
		t.Helper()
		select {
		case f := <-wire.out:
			return f
		case <-ctx.Done():
			t.Fatal(ctx.Err())
			return record{}
		}
	}
	for _, part := range [][]byte{payload[:chunkSize], payload[chunkSize:]} {
		if f := next(); f.control || !bytes.Equal([]byte(f.data), part) {
			t.Fatal("binary chunk changed")
		}
	}
	if got := next(); got != (record{"FIN", true}) {
		t.Fatalf("expected FIN, got %+v", got)
	}
	wire.in <- record{"\x00reply\xff", false}
	wire.in <- record{"FIN", true}
	if got := next(); got != (record{"ACK", true}) {
		t.Fatalf("expected ACK, got %+v", got)
	}
	wire.in <- record{"ACK", true}
	close(wire.in)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if end.String() != "\x00reply\xff" || !end.halfClosed || !wire.closed {
		t.Fatal("incomplete payload or shutdown")
	}
}

func TestReceiveRejectsOutOfOrderOrIncompleteShutdown(t *testing.T) {
	fin, ack := record{"FIN", true}, record{"ACK", true}
	for _, tc := range []struct {
		name    string
		sentFIN bool
		frames  []record
		want    string
	}{
		{"missing acknowledgement", true, []record{fin}, io.ErrUnexpectedEOF.Error()},
		{"early acknowledgement", false, []record{ack}, "unexpected FIN acknowledgement"},
		{"duplicate acknowledgement", true, []record{ack, ack}, "unexpected FIN acknowledgement"},
		{"duplicate FIN", true, []record{fin, fin}, "duplicate FIN"},
		{"payload after FIN", true, []record{fin, {"late", false}}, "received bytes after FIN"},
		{"unknown control", true, []record{{"other", true}}, "unknown stream control record"},
		{"data after shutdown", true, []record{ack, fin, {"extra", false}}, "unexpected record after stream shutdown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := newMemoryChannel()
			for _, frame := range tc.frames {
				wire.in <- frame
			}
			close(wire.in)
			var sent atomic.Bool
			sent.Store(tc.sentFIN)
			end := &memoryEndpoint{}
			err := receive(t.Context(), wire, end, func([]byte, bool) error { return nil }, &sent)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
}

func TestCancelUnblocksTheWireAndLocalReader(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	stop := errors.New("menu closed")
	r, w := io.Pipe()
	defer w.Close()
	wire := newMemoryChannel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, wire, &memoryEndpoint{ReadCloser: r}) }()
	select {
	case <-wire.reading:
	case <-time.After(3 * time.Second):
		t.Fatal("wire read did not start")
	}
	cancel(stop)
	select {
	case err := <-done:
		if !errors.Is(err, stop) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bridge ignored cancellation")
	}
	select {
	case <-wire.interrupted:
	default:
		t.Fatal("wire read still blocked")
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("local reader still open", err)
	}
}

type failingStreamEndpoint struct {
	*memoryEndpoint
	writeErr, halfErr error
}

func (e failingStreamEndpoint) Write([]byte) (int, error) { return 0, e.writeErr }
func (e failingStreamEndpoint) CloseWrite() error         { return e.halfErr }

type bridgeWriterError struct {
	*memoryChannel
	err error
}

func (c bridgeWriterError) WriteDataChannel([]byte, bool) (int, error) { return 0, c.err }

func TestBridgePropagatesEndpointAndACKFailures(t *testing.T) {
	failure := errors.New("test stream failure")
	cases := []struct {
		name                      string
		rec                       record
		writeErr, halfErr, ackErr error
		ackCalls                  int
	}{
		{name: "endpoint write", rec: record{data: "output"}, writeErr: failure},
		{name: "half close", rec: record{data: "FIN", control: true}, halfErr: failure},
		{name: "acknowledgement write", rec: record{data: "FIN", control: true}, ackErr: failure, ackCalls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := newMemoryChannel()
			wire.in <- tc.rec
			end := failingStreamEndpoint{&memoryEndpoint{}, tc.writeErr, tc.halfErr}
			var ackCalls int
			err := receive(t.Context(), wire, end, func(p []byte, text bool) error {
				ackCalls++
				if string(p) != "ACK" || !text {
					t.Fatal("invalid acknowledgement")
				}
				return tc.ackErr
			}, new(atomic.Bool))
			if !errors.Is(err, failure) || ackCalls != tc.ackCalls {
				t.Fatalf("got err=%v, acknowledgements=%d", err, ackCalls)
			}
		})
	}
}

func TestBridgeDoesNotLoseSenderWriteError(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	failure := errors.New("test send failure")
	end := &memoryEndpoint{ReadCloser: io.NopCloser(bytes.NewBufferString("payload"))}
	wire := bridgeWriterError{newMemoryChannel(), failure}
	if err := Run(ctx, wire, end); !errors.Is(err, failure) {
		t.Fatalf("got %v, want %v", err, failure)
	}
}

func TestBridgePreCanceledContextClosesEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	wire := newMemoryChannel()
	reader := &trackedEndpointReader{Reader: bytes.NewReader(nil)}
	if err := Run(ctx, wire, &memoryEndpoint{ReadCloser: reader}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled bridge returned %v", err)
	}
	if !reader.closed {
		t.Fatal("canceled bridge left its endpoint open")
	}
	select {
	case <-wire.reading:
		t.Fatal("canceled bridge read from channel")
	default:
	}
}

type trackedEndpointReader struct {
	io.Reader
	closed bool
}

func (r *trackedEndpointReader) Close() error { r.closed = true; return nil }
