package active

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pion/datachannel"
	"peertty/internal/grant"
)

type controllerFixturePeer struct {
	workerPeer // Unused operations fail if the controller mistakenly invokes them.
	ctx        context.Context
	answer     func(context.Context, string) (string, error)
	bind       func([]byte) error
	channel    func(context.Context) (datachannel.ReadWriteCloserDeadliner, string, error)
	closed     bool
	up, moved  bool
}

func (p *controllerFixturePeer) Context() context.Context { return p.ctx }
func (p *controllerFixturePeer) Answer(ctx context.Context, offer string) (string, error) {
	return p.answer(ctx, offer)
}
func (p *controllerFixturePeer) BindGrant(signature []byte) error { return p.bind(signature) }
func (p *controllerFixturePeer) Channel(ctx context.Context) (datachannel.ReadWriteCloserDeadliner, string, error) {
	return p.channel(ctx)
}
func (p *controllerFixturePeer) Connected() bool { return p.up }
func (p *controllerFixturePeer) Migrated() bool  { return p.moved }
func (p *controllerFixturePeer) Close() error {
	p.closed = true
	return nil
}

type controllerFixtureChannel struct {
	datachannel.ReadWriteCloserDeadliner
	closed bool
}

func (*controllerFixtureChannel) ReadDataChannel([]byte) (int, bool, error) {
	return 0, false, io.EOF
}
func (s *controllerFixtureChannel) Close() error {
	s.closed = true
	return nil
}

func TestControllerWorkerStartupAndClosure(t *testing.T) {
	hostPub, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	controlPub, control, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := grant.NewLoginOffer(host, "fixture offer", "approved", hostPub, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	fixtureErr := errors.New("fixture transport failed")
	for _, tc := range []struct {
		name, fail, user, calls, phase string
		want                           error
		scoped, badStore               bool
	}{
		{name: "answer failure", fail: "answer", calls: "a", phase: "gathering", want: fixtureErr},
		{name: "scoped user mismatch", user: "other", scoped: true, calls: "a", phase: "gathering"},
		{name: "cannot create private scoped login key", fail: "key", user: "approved", scoped: true, calls: "a", phase: "gathering", want: os.ErrExist},
		{name: "cannot publish scoped host key", fail: "pin", user: "approved", scoped: true, calls: "a", phase: "gathering"},
		{name: "publish failure", fail: "write", calls: "a", phase: "gathering", want: os.ErrExist},
		{name: "binding failure", fail: "bind", calls: "ab", phase: "waiting", want: fixtureErr},
		{name: "route missing", fail: "channel", calls: "abc", phase: "waiting", want: fixtureErr},
		{name: "ready then stream closes", user: "approved", scoped: true, calls: "abc", phase: "ready", want: io.EOF},
		{name: "trust history storage unavailable", badStore: true, calls: "abc", phase: "ready", want: io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			dir := t.TempDir()
			identity := filepath.Join(dir, "device.key")
			if tc.badStore {
				if err := os.WriteFile(identity+".peertty", []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, "session.answer")
			switch tc.fail {
			case "key":
				if err := os.WriteFile(filepath.Join(dir, "login.key"), []byte("existing key fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			case "pin":
				if err := os.Mkdir(filepath.Join(dir, "known_hosts"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.fail == "write" {
				if err := os.WriteFile(path, []byte("keep this"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var calls strings.Builder
			channel := &controllerFixtureChannel{}
			p := &controllerFixturePeer{ctx: ctx, up: true}
			p.answer = func(_ context.Context, remote string) (string, error) {
				calls.WriteByte('a')
				if remote != offer.Claims.SDP {
					t.Fatal("passed another offer to transport")
				}
				if tc.fail == "answer" {
					return "", fixtureErr
				}
				return "fixture answer", nil
			}
			p.bind = func(signature []byte) error {
				calls.WriteByte('b')
				answer, err := grant.Read(path)
				if err != nil || answer.VerifyAnswer(offer, time.Now()) != nil ||
					!bytes.Equal(signature, answer.Signature) || (len(answer.Claims.SSHLoginKey) != 0) != tc.scoped ||
					!bytes.Equal(answer.Claims.Issuer, controlPub) {
					t.Fatalf("did not bind session to the published signed answer: %v", err)
				}
				if tc.fail == "bind" {
					return fixtureErr
				}
				return nil
			}
			p.channel = func(context.Context) (datachannel.ReadWriteCloserDeadliner, string, error) {
				calls.WriteByte('c')
				if tc.fail == "channel" {
					return nil, "", fixtureErr
				}
				return channel, "fixture direct route", nil
			}
			w := worker{Options: Options{PairingCode: fixtureCode, Role: "control", Key: identity, User: tc.user, Offer: offer, Scoped: tc.scoped}, key: control, dir: dir,
				state: State{ID: "fixture", Role: "control", Phase: "gathering", Deadline: offer.Deadline()}}
			err := w.runWithPeer(ctx, p)
			if tc.fail == "pin" {
				var pathErr *os.PathError
				if !errors.As(err, &pathErr) || pathErr.Path != filepath.Join(dir, "known_hosts") {
					t.Fatalf("pin storage failure was obscured: %v", err)
				}
			} else if tc.want != nil && !errors.Is(err, tc.want) || tc.want == nil && (err == nil || !strings.Contains(err.Error(), "不包含该登录账号")) {
				t.Fatalf("run = %v, expected %v", err, tc.want)
			}
			if tc.fail == "key" || tc.fail == "pin" {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("receipt published without private login or host pin: %v", err)
				}
			}

			if calls.String() != tc.calls || !p.closed || channel.closed != (tc.phase == "ready") {
				t.Fatalf("calls=%q peer closed=%v channel closed=%v", calls.String(), p.closed, channel.closed)
			}
			if tc.fail == "write" {
				b, err := os.ReadFile(path)
				if err != nil || string(b) != "keep this" {
					t.Fatal("preexisting receipt overwritten")
				}
			}
			st := w.snapshot()
			if st.Phase != tc.phase || strings.Contains(st.Note, "无法保存设备信任记录") {
				t.Fatalf("state = %+v", st)
			}
			if tc.phase == "ready" {
				if st.Exchange != path || st.Route != "fixture direct route" || (st.KnownHosts != "") != tc.scoped {
					t.Fatalf("missing linked state: %+v", st)
				}
				p.up = false
				if st := w.snapshot(); st.Phase != "disconnected" {
					t.Fatalf("loss not visible: %+v", st)
				}
				p.up, p.moved = true, true
				if st := w.snapshot(); st.Phase != "ready" || !strings.Contains(st.Route, "换网") {
					t.Fatalf("recovered route not visible: %+v", st)
				}
			}
		})
	}
}

func TestWorkerReportsInvalidDiscoveryConfigBeforeExchange(t *testing.T) {
	w := &worker{Options: Options{STUN: "invalid fixture value"}}
	if err := w.run(t.Context()); err == nil || !strings.Contains(err.Error(), "STUN 地址") {
		t.Fatalf("invalid network config = %v", err)
	}
}

type workerClosureFixture struct {
	controllerFixtureChannel
	cancelOnRead context.CancelFunc
	request      []byte
	writeErr     error
	ack          chan struct{}
	done         chan struct{}
	deadline     time.Time
	output       string
	text         bool
}

func (s *workerClosureFixture) ReadDataChannel(buf []byte) (int, bool, error) {
	defer close(s.done)
	if s.cancelOnRead != nil {
		s.cancelOnRead()
		<-s.ack
		if s.writeErr != nil {
			return 0, false, io.ErrClosedPipe
		}
		return copy(buf, "CLOSED"), true, nil
	}
	return copy(buf, s.request), true, nil
}

func (s *workerClosureFixture) SetWriteDeadline(deadline time.Time) error {
	s.deadline = deadline
	return nil
}

func (s *workerClosureFixture) WriteDataChannel(buf []byte, text bool) (int, error) {
	s.output, s.text = string(buf), text
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	if s.cancelOnRead != nil {
		close(s.ack)
	}
	return len(buf), nil
}

func (s *workerClosureFixture) Close() error {
	if s.cancelOnRead != nil && s.writeErr != nil {
		close(s.ack)
	}
	return s.controllerFixtureChannel.Close()
}

func TestControllerGrantClosureAfterConnection(t *testing.T) {
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, control, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := grant.NewLoginOffer(host, "fixture offer", "user", nil, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		remote   bool
		writeErr error
	}{
		{name: "local revoke waits for peer acknowledgment"},
		{name: "local revoke still ends when acknowledgment is unreachable", writeErr: io.ErrClosedPipe},
		{name: "remote revoke is acknowledged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peerCtx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			ctx, cancel := context.WithCancel(peerCtx)
			defer cancel()
			offeredStream := &workerClosureFixture{ack: make(chan struct{}), done: make(chan struct{}), writeErr: tc.writeErr}
			wantErr, wantTransition := error(context.Canceled), "REVOKE"
			if tc.remote {
				offeredStream.request = []byte("REVOKE")
				wantErr, wantTransition = nil, "CLOSED"
			} else {
				offeredStream.cancelOnRead = cancel
			}
			dir := t.TempDir()
			w := worker{Options: Options{PairingCode: fixtureCode, Role: "control", Key: filepath.Join(dir, "identity"), Offer: offer}, key: control, dir: dir,
				state: State{ID: "closure", Role: "control", Phase: "gathering", Deadline: offer.Deadline()}}
			peer := &controllerFixturePeer{
				ctx:    peerCtx,
				answer: func(context.Context, string) (string, error) { return "fixture answer", nil },
				bind:   func([]byte) error { return nil },
				channel: func(context.Context) (datachannel.ReadWriteCloserDeadliner, string, error) {
					return offeredStream, "fixture route", nil
				},
				up: true,
			}
			start := time.Now()
			if err := w.runWithPeer(ctx, peer); !errors.Is(err, wantErr) {
				t.Fatalf("worker stopped with %v, want %v", err, wantErr)
			}
			select {
			case <-offeredStream.done:
			case <-peerCtx.Done():
				t.Fatal("closing control stream left a reader blocked")
			}
			if !peer.closed || !offeredStream.closed || offeredStream.output != wantTransition || !offeredStream.text {
				t.Fatalf("peer closed=%v, stream closed=%v, message=%q, text=%v",
					peer.closed, offeredStream.closed, offeredStream.output, offeredStream.text)
			}
			if d := offeredStream.deadline; !d.After(start) || d.After(time.Now().Add(2*time.Second)) {
				t.Fatalf("write not bounded: %v", d)
			}
		})
	}
}
