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

type hostFixturePeer struct {
	controllerFixturePeer
	offerErr, acceptErr error
	roam                bool
	linked              bool
	accepted            string
}

func (p *hostFixturePeer) Offer(context.Context) (string, error) {
	return "host fixture offer", p.offerErr
}
func (p *hostFixturePeer) Accept(v string) error                               { p.accepted = v; return p.acceptErr }
func (p *hostFixturePeer) CanRoam() bool                                       { return p.roam }
func (p *hostFixturePeer) OnLink(f func(datachannel.ReadWriteCloserDeadliner)) { p.linked = f != nil }

func TestHostWorkerOnlyNegotiatesAfterApprovalAndKeepsRecoverableGrant(t *testing.T) {
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, control, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("fixture refused")
	for _, tc := range []struct {
		name, fail, wantText string
		want                 error
		timeout, roam        bool
		calls                int
	}{
		{name: "offer gathering failure", fail: "offer", want: refused},
		{name: "cannot publish invitation safely", fail: "write", want: os.ErrExist},
		{name: "cancel while waiting for approval", fail: "cancel", want: context.Canceled},
		{name: "accept failed", fail: "accept", want: refused},
		{name: "link established and then closed", calls: 1, want: io.EOF},
		{name: "nonroaming peer times out", timeout: true, calls: 1, wantText: "批准后 60 秒内未建立直连"},
		{name: "roaming grant keeps waiting and recovers", timeout: true, roam: true, calls: 2, want: io.EOF},
		{name: "roaming grant reports path failure", timeout: true, roam: true, calls: 2, fail: "route", want: refused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			dir := t.TempDir()
			path := filepath.Join(dir, "session.offer")
			if tc.fail == "write" {
				if err := os.WriteFile(path, []byte("existing invite"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			w := &worker{
				Options: Options{PairingCode: fixtureCode, Role: "host", Port: 2222, Key: filepath.Join(dir, "device.key")},
				dir:     dir, key: host, approval: make(chan grant.Ticket, 1),
				state: State{PairingCode: fixtureCode, ID: "fixture", Role: "host", Phase: "gathering", Deadline: time.Now().Add(time.Minute)},
			}
			p := &hostFixturePeer{controllerFixturePeer: controllerFixturePeer{ctx: ctx, up: true}, roam: tc.roam}
			if tc.fail == "offer" {
				p.offerErr = refused
			}
			if tc.fail == "accept" {
				p.acceptErr = refused
			}
			channel := &controllerFixtureChannel{}
			var signed []byte
			calls := 0
			p.bind = func(sig []byte) error {
				if !bytes.Equal(sig, signed) || p.accepted != "approved fixture answer" || !p.linked {
					return errors.New("worker did not bind the actual approved receipt")
				}
				return nil
			}
			p.channel = func(negotiation context.Context) (datachannel.ReadWriteCloserDeadliner, string, error) {
				calls++
				if calls == 1 {
					if negotiation == ctx {
						return nil, "", errors.New("initial negotiation lacked its own cancellation scope")
					}
					if tc.timeout {
						return nil, "", context.DeadlineExceeded
					}
				} else if negotiation != ctx || !strings.Contains(w.snapshot().Note, "授权期内继续等待") {
					return nil, "", errors.New("recovery did not preserve grant lifetime or notice")
				}
				if tc.fail == "route" {
					return nil, "", refused
				}
				return channel, "direct fixture route", nil
			}
			done := make(chan error, 1)
			go func() { done <- w.runWithPeer(ctx, p) }()
			if tc.fail != "offer" && tc.fail != "write" {
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				for {
					if w.snapshot().Phase == "waiting" {
						break
					}
					select {
					case early := <-done:
						t.Fatalf("worker ended before waiting: %v", early)
					case <-ctx.Done():
						t.Fatal("never published the invitation")
					case <-tick.C:
					}
				}
				if tc.fail == "cancel" {
					cancel()
				} else {
					offer, err := grant.Read(path)
					if err != nil || offer.Claims.SDP != "host fixture offer" {
						t.Fatalf("failed to publish correct invitation: %v", err)
					}
					answer, err := grant.NewLoginAnswer(control, offer, "approved fixture answer", nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := fixtureCode.Seal(&answer); err != nil {
						t.Fatal(err)
					}
					signed = answer.Signature
					if _, _, _, err := w.acceptRequest(ctx, request{ID: "fixture", Op: "approve", Answer: &answer}, time.Now()); err != nil {
						t.Fatal(err)
					}
				}
			}
			var runErr error
			select {
			case runErr = <-done:
			case <-time.After(4 * time.Second):
				t.Fatal("worker did not stop")
			}
			if tc.want != nil && !errors.Is(runErr, tc.want) || tc.wantText != "" && (runErr == nil || !strings.Contains(runErr.Error(), tc.wantText)) {
				t.Fatalf("run=%v, expected %v / %q", runErr, tc.want, tc.wantText)
			}
			wantReady := tc.want == io.EOF
			if calls != tc.calls || !p.closed || channel.closed != wantReady {
				t.Fatalf("calls=%d closed peer=%v channel=%v", calls, p.closed, channel.closed)
			}
			if w.snapshot().Phase == "ready" != wantReady || wantReady && w.snapshot().Note != "" {
				t.Fatalf("wrong final phase or stale warning: %+v", w.snapshot())
			}
			if tc.fail == "cancel" && (p.linked || p.accepted != "") {
				t.Fatal("unapproved grant attempted connection")
			}
		})
	}
}
