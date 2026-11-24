package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pion/datachannel"

	"peertty/internal/bridge"
	"peertty/internal/grant"
)

type sessionStub struct {
	ctx       context.Context
	calls     *[]string
	fail      string
	err       error
	onChannel func()
}

func (p *sessionStub) call(name string) error {
	*p.calls = append(*p.calls, name)
	if p.fail == name {
		return p.err
	}
	return nil
}

func (p *sessionStub) Context() context.Context { return p.ctx }
func (p *sessionStub) Close() error             { return p.call("close peer") }
func (p *sessionStub) Offer(context.Context) (string, error) {
	return "local invitation", p.call("offer")
}
func (p *sessionStub) Answer(_ context.Context, offer string) (string, error) {
	return "local reply", p.call("answer " + offer)
}
func (p *sessionStub) Accept(answer string) error { return p.call("accept " + answer) }
func (p *sessionStub) Channel(context.Context) (datachannel.ReadWriteCloserDeadliner, string, error) {
	if p.onChannel != nil {
		p.onChannel()
	}
	return nil, "unit route", p.call("channel")
}

type localSessionStub struct {
	bridge.Endpoint
	calls     *[]string
	temporary bool
	err       error
}

func (p *localSessionStub) Temporary() bool { return p.temporary }
func (p *localSessionStub) Release() error {
	*p.calls = append(*p.calls, "release")
	return p.err
}

func newSessionKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}

func TestHostSessionTransitions(t *testing.T) {
	_, host := newSessionKeys(t)
	operator, key := newSessionKeys(t)
	stageErr, releaseErr := errors.New("stage failed"), errors.New("release failed")
	hostFlow := []string{"peer", "offer", "exchange", "accept local reply", "channel", "open", "connected", "run", "release", "close peer"}
	for _, tc := range []struct {
		name, fail, message string
		pair, cancel        bool
		n                   int
		failure             error
	}{
		{name: "pinned success", n: 9},
		{name: "local approval pairing success", pair: true, n: 9},
		{name: "no transport", fail: "peer", n: 1, failure: stageErr},
		{name: "no invitation", fail: "offer", n: 2, failure: stageErr},
		{name: "declined", fail: "exchange", n: 3, failure: stageErr},
		{name: "no matching approval", fail: "empty reply", n: 3, message: "回执"},
		{name: "bad remote description", fail: "accept local reply", n: 4, failure: stageErr},
		{name: "connection failure", fail: "channel", n: 5, failure: stageErr, message: "establish direct path"},
		{name: "approval wait timed out", fail: "channel", n: 5, message: "批准后", failure: context.DeadlineExceeded},
		{name: "overall lifetime ended", fail: "channel", n: 5, message: "establish direct path", failure: context.DeadlineExceeded, cancel: true},
		{name: "local OpenSSH unavailable", fail: "open", n: 6, failure: stageErr},
		{name: "bridge failure also releases SSH", fail: "run", n: 9, failure: stageErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls []string
			peer := &sessionStub{calls: &calls, fail: tc.fail, err: tc.failure}
			if tc.cancel {
				peer.onChannel = cancel
			}
			local := &localSessionStub{calls: &calls, temporary: tc.pair}
			if tc.fail == "run" {
				local.err = releaseErr
			}
			deps := sessionIO{
				peer: func(ctx context.Context, spec string) (sessionPeer, error) {
					if spec != "none" {
						t.Fatalf("STUN = %q", spec)
					}
					peer.ctx = ctx
					return peer, peer.call("peer")
				},
				open: func(ctx context.Context, port int) (localEndpoint, error) {
					if ctx != peer.ctx || port != 2222 {
						t.Fatalf("wrong local SSH request: %d", port)
					}
					return local, peer.call("open")
				},
				run: func(ctx context.Context, _ bridge.Channel, end bridge.Endpoint) error {
					if ctx != peer.ctx || end != local {
						t.Fatal("connected session used the wrong endpoint")
					}
					return peer.call("run")
				},
			}
			cfg := Config{Key: host, STUN: "none", PairOnApproval: tc.pair}
			if !tc.pair {
				cfg.Peer = grant.Fingerprint(operator)
			}
			err := deps.host(ctx, cfg, time.Minute, 2222, func(ctx context.Context, offer grant.Ticket, code grant.PairingCode) (grant.Ticket, error) {
				if ctx != peer.ctx || offer.Claims.Recipient != cfg.Peer || offer.Claims.SDP != "local invitation" {
					t.Fatal("wrong invitation passed to approval")
				}
				if err := peer.call("exchange"); err != nil || tc.fail == "empty reply" {
					return grant.Ticket{}, err
				}
				answer, err := grant.NewAnswer(key, offer, "local reply")
				if err == nil {
					err = code.Seal(&answer)
				}
				return answer, err
			}, func(route string, temporary bool) {
				calls = append(calls, "connected")
				if route != "unit route" || temporary != tc.pair {
					t.Fatalf("wrong connection status: %q, temp=%v", route, temporary)
				}
			})
			want := slices.Clone(hostFlow[:tc.n])
			if tc.n > 1 {
				want = append(want, "close peer")
			}
			if !slices.Equal(calls, want) {
				t.Fatalf("calls = %v, want %v", calls, want)
			}
			switch {
			case tc.message != "":
				if err == nil || !strings.Contains(err.Error(), tc.message) || (tc.failure != nil && !errors.Is(err, tc.failure) && tc.message != "批准后") {
					t.Fatalf("got %v, want %q", err, tc.message)
				}
			default:
				if !errors.Is(err, tc.failure) {
					t.Fatalf("got %v, want %v", err, tc.failure)
				}
			}
			if tc.fail == "run" && !errors.Is(err, releaseErr) {
				t.Fatalf("release failure lost: %v", err)
			}
		})
	}
}

func TestControllerStopsBeforeConnectingOnError(t *testing.T) {
	hostPub, hostKey := newSessionKeys(t)
	operator, key := newSessionKeys(t)
	offer, err := grant.NewOffer(hostKey, grant.Fingerprint(operator), "remote invitation", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("stage failed")
	steps := []string{"peer", "answer remote invitation", "publish", "channel", "connected", "run"}
	for _, tc := range []struct {
		fail string
		n    int
	}{
		{"unverified offer", 0},
		{"peer", 1},
		{"answer remote invitation", 2},
		{"publish", 3},
		{"channel", 4},
		{"run", 6},
		{"", 6},
	} {
		t.Run(tc.fail, func(t *testing.T) {
			var calls []string
			peer := &sessionStub{calls: &calls, fail: tc.fail, err: boom}
			end := &localSessionStub{}
			deps := sessionIO{
				peer: func(ctx context.Context, _ string) (sessionPeer, error) {
					peer.ctx = ctx
					return peer, peer.call("peer")
				},
				run: func(ctx context.Context, _ bridge.Channel, e bridge.Endpoint) error {
					if ctx != peer.ctx || end != e {
						t.Fatal("incorrect controller endpoint")
					}
					return peer.call("run")
				},
			}
			settings := Config{Key: key, PairingCode: fixtureCode, Peer: grant.Fingerprint(hostPub), Profile: filepath.Join(t.TempDir(), "controller")}
			invitation := offer
			if err := fixtureCode.Seal(&invitation); err != nil {
				t.Fatal(err)
			}
			if tc.n == 0 {
				invitation = grant.Ticket{}
			}
			err := deps.control(t.Context(), settings, invitation, end, func(answer grant.Ticket) error {
				if err := answer.VerifyAnswer(offer, time.Now()); err != nil || answer.Claims.SDP != "local reply" {
					t.Fatalf("not a valid reply: %v", err)
				}
				return peer.call("publish")
			}, func(route string) {
				if route != "unit route" {
					t.Fatalf("route = %q", route)
				}
				calls = append(calls, "connected")
			})
			want := slices.Clone(steps[:tc.n])
			if tc.n > 1 {
				want = append(want, "close peer")
			}
			if !slices.Equal(calls, want) {
				t.Fatalf("calls=%v, want %v", calls, want)
			}
			switch {
			case tc.n == 0 && err == nil:
				t.Fatal("an invalid invite was accepted")
			case tc.n != 0 && tc.fail != "" && !errors.Is(err, boom):
				t.Fatalf("lost stage error: %v", err)
			case tc.fail == "" && err != nil:
				t.Fatal(err)
			}
		})
	}
}

func TestFileAdaptersPublishAndReportConnectedState(t *testing.T) {
	hostPub, host := newSessionKeys(t)
	opPub, operator := newSessionKeys(t)
	dir := t.TempDir()
	offerPath, replyPath := filepath.Join(dir, "offer"), filepath.Join(dir, "reply")
	var calls []string
	peer := &sessionStub{calls: &calls}
	tmpSSH := true
	deps := sessionIO{
		peer: func(ctx context.Context, _ string) (sessionPeer, error) { peer.ctx = ctx; return peer, nil },
		open: func(context.Context, int) (localEndpoint, error) {
			return &localSessionStub{calls: &calls, temporary: tmpSSH}, nil
		},
		run: func(context.Context, bridge.Channel, bridge.Endpoint) error { return nil },
	}
	for _, mode := range []string{"missing reply", "temporary SSH", "existing SSH"} {
		t.Run(mode, func(t *testing.T) {
			offerPath := filepath.Join(t.TempDir(), "host.offer")
			replyPath := filepath.Join(t.TempDir(), "controller.reply")
			var hostStatus bytes.Buffer
			hostOptions := HostOptions{
				Options: Options{Key: host, Peer: grant.Fingerprint(opPub), OfferPath: offerPath, Status: &hostStatus},
				TTL:     time.Minute, SSHPort: 2222,
				Approval: func(_ context.Context, code grant.PairingCode) (string, error) {
					if mode == "missing reply" {
						return replyPath, nil
					}
					invite, err := grant.Read(offerPath)
					if err != nil {
						return "", err
					}
					reply, err := grant.NewAnswer(operator, invite, "local reply")
					if err != nil {
						return "", err
					}
					if err := code.Seal(&reply); err != nil {
						return "", err
					}
					return replyPath, reply.WriteNew(replyPath)
				},
			}
			tmpSSH = mode == "temporary SSH"
			err := deps.fileHost(t.Context(), hostOptions)
			if mode == "missing reply" {
				if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "read answer") {
					t.Fatalf("missing file error: %v", err)
				}
				return
			}
			if err != nil || !strings.Contains(hostStatus.String(), "Direct path established (unit route)") ||
				strings.Contains(hostStatus.String(), "Started temporary OpenSSH") != tmpSSH {
				t.Fatalf("file host output: %q, err: %v", hostStatus.String(), err)
			}
		})
	}
	invitation, err := grant.NewOffer(host, grant.Fingerprint(opPub), "remote invitation", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixtureCode.Seal(&invitation); err != nil {
		t.Fatal(err)
	}
	if err := invitation.WriteNew(offerPath); err != nil {
		t.Fatal(err)
	}
	var status bytes.Buffer
	o := Options{PairingCode: fixtureCode, Key: operator, Peer: grant.Fingerprint(hostPub), Profile: filepath.Join(t.TempDir(), "controller"), OfferPath: offerPath, Status: &status}
	if err := deps.fileConnect(t.Context(), o, replyPath, nil); err != nil {
		t.Fatal(err)
	}
	reply, err := grant.Read(replyPath)
	if err != nil || reply.VerifyAnswer(invitation, time.Now()) != nil ||
		!strings.Contains(status.String(), "Return "+replyPath) || !strings.Contains(status.String(), "Direct path established") {
		t.Fatalf("file controller response: %q, %v", status.String(), err)
	}
	status.Reset()
	if err := deps.fileConnect(t.Context(), o, replyPath+".new", nil); !errors.Is(err, grant.ErrOfferUsed) || status.Len() != 0 {
		t.Fatalf("duplicate reply: %v, status %q", err, status.String())
	}
	newOffer, err := grant.NewOffer(host, grant.Fingerprint(opPub), "new invitation", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixtureCode.Seal(&newOffer); err != nil {
		t.Fatal(err)
	}
	o.OfferPath = offerPath + ".new"
	if err := newOffer.WriteNew(o.OfferPath); err != nil {
		t.Fatal(err)
	}
	if err := deps.fileConnect(t.Context(), o, replyPath, nil); !errors.Is(err, os.ErrExist) || status.Len() != 0 {
		t.Fatalf("fresh offer overwrote an existing reply: %v, status %q", err, status.String())
	}
}
