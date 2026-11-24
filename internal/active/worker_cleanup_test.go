package active

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestPeerTerminationResolution(t *testing.T) {
	transportEnded := errors.New("fixture peer ended")
	peerReceipt := errors.New("fixture peer closure report")
	for _, tc := range []struct {
		name, action string
		want         error
	}{
		{"peer closure report beats transport fallback", "receipt", peerReceipt},
		{"local cancellation interrupts peer grace period", "cancel", context.Canceled},
		{"missing closure report preserves transport cause", "fallback", transportEnded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				peer, end := context.WithCancelCause(t.Context())
				defer end(nil)
				remote := make(chan error, 1)
				done := make(chan error, 1)
				go func() {
					done <- waitForGrantEndEvents(ctx, peer, func() bool { return true }, remote, nil, func() {}, nil)
				}()
				synctest.Wait()
				end(transportEnded)
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatalf("peer shutdown skipped closure grace period: %v", err)
				default:
				}
				switch tc.action {
				case "receipt":
					remote <- peerReceipt
				case "cancel":
					cancel()
				case "fallback":
					time.Sleep(250 * time.Millisecond)
				}
				if err := <-done; !errors.Is(err, tc.want) {
					t.Fatalf("closure outcome = %v, want %v", err, tc.want)
				}
			})
		})
	}
}

func TestHostTerminalCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, note            string
		cancel, stop, listens bool
	}{
		{name: "obsolete link context", cancel: true},
		{name: "stopping grant cannot open a local terminal", stop: true},
		{name: "local service connection failure", note: "连接本机 SSH"},
		{name: "peer stream closes after connecting to local endpoint", listens: true, note: "SSH 终端已断开"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			// A negative port cannot dial and cannot trigger default SSH activation.
			w := &worker{Options: Options{Port: -1}, stopping: tc.stop}
			var listener net.Listener
			if tc.listens {
				l, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				listener = l
				w.Port = l.Addr().(*net.TCPAddr).Port
			}
			if tc.cancel {
				cancel()
			}
			stream := &admittedFixtureStream{}
			done := make(chan struct{})
			go func() {
				w.serveSSH(ctx, stream, false)
				close(done)
			}()
			if listener != nil {
				l := listener.(*net.TCPListener)
				if err := l.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				c, err := l.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
			}
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				t.Fatal("terminal handler did not exit")
			}
			w.links.Wait()
			state := w.snapshot()
			if !stream.closed || state.Terminals != 0 || tc.note == "" && state.Note != "" ||
				tc.note != "" && !strings.Contains(state.Note, tc.note) {
				t.Fatalf("cleanup state = %+v, stream closed=%v, expected note %q", state, stream.closed, tc.note)
			}
		})
	}
}
