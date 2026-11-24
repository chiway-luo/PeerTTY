package active

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/datachannel"
)

type workerAdmissionPeer struct {
	controllerFixturePeer
	open func(context.Context) (datachannel.ReadWriteCloserDeadliner, error)
}

func (p *workerAdmissionPeer) OpenLink(ctx context.Context) (datachannel.ReadWriteCloserDeadliner, error) {
	return p.open(ctx)
}

type admittedFixtureStream struct {
	controllerFixtureChannel
}

func (*admittedFixtureStream) SetReadDeadline(time.Time) error  { return nil }
func (*admittedFixtureStream) SetWriteDeadline(time.Time) error { return nil }
func (*admittedFixtureStream) WriteDataChannel(b []byte, _ bool) (int, error) {
	return len(b), nil
}

func TestWorkerHandleTerminalAdmission(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := localTLS(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		full, up   bool
		open       bool
		err        error
	}{
		{name: "disconnected grant rejects terminal", want: "尚未建立"},
		{name: "full grant rejects terminal without opening a link", up: true, full: true, want: "终端数已达上限"},
		{name: "transport failure releases terminal slot", up: true, open: true, err: errors.New("fixture route unavailable"), want: "fixture route unavailable"},
		{name: "approved connection opens and releases a terminal", up: true, open: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			stream := &admittedFixtureStream{}
			calls := 0
			p := &workerAdmissionPeer{controllerFixturePeer: controllerFixturePeer{up: tc.up}}
			w := &worker{peer: p, state: State{Role: "control", Phase: "ready", ID: "fixture"}}
			w.resetLinks(ctx)
			defer w.endLinks()
			if tc.full {
				for range 32 {
					if !w.enter() {
						t.Fatal("could not reserve fixture slot")
					}
					defer w.leave()
				}
			}
			base := w.snapshot().Terminals
			p.open = func(openCtx context.Context) (datachannel.ReadWriteCloserDeadliner, error) {
				calls++
				if actual := w.snapshot().Terminals; actual != base+1 {
					return nil, errors.New("terminal slot was not reserved before opening")
				}
				if _, bounded := openCtx.Deadline(); !bounded {
					return nil, errors.New("link opening has no deadline")
				}
				if tc.err != nil {
					return nil, tc.err
				}
				return stream, nil
			}
			done := make(chan error, 1)
			go func() {
				raw, err := ln.Accept()
				if err == nil {
					w.handle(ctx, tls.Server(raw, cfg), cancel)
				}
				done <- err
			}()
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp4", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			c := tls.Client(raw, cfg)
			defer c.Close()
			deadline, _ := ctx.Deadline()
			if err = c.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err = send(c, request{Op: "link", ID: "fixture"}); err != nil {
				t.Fatal(err)
			}
			var reply reply
			if err = receive(c, &reply); err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && !strings.Contains(reply.Error, tc.want) ||
				tc.want == "" && (reply.Error != "" || reply.State.ID != "fixture" || reply.State.Phase != "ready") {
				t.Fatalf("reply = %+v, expected error %q or ready", reply, tc.want)
			}
			if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("handler did not close its connection: n=%d err=%v", n, err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("terminal handler did not exit")
			}
			if (calls == 1) != tc.open || calls > 1 || w.snapshot().Terminals != base || stream.closed != (tc.want == "") {
				t.Fatalf("open calls=%d, slots=%d (started at %d), stream closed=%v", calls, w.snapshot().Terminals, base, stream.closed)
			}
		})
	}
}
