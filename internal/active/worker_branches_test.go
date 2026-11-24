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
	"sync/atomic"
	"testing"
	"time"

	"peertty/internal/grant"
)

func TestWorkerRequestStateMachine(t *testing.T) {
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, operator, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	offer, err := grant.NewLoginOffer(host, "test offer", "", nil, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	answer, err := grant.NewLoginAnswer(operator, offer, "test reply", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixtureCode.Seal(&answer); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, role, phase, op, id, wantErr          string
		answer                                      *grant.Ticket
		stopping, canceled, scoped, approves, stops bool
	}{
		{name: "status after stop", op: "status", stopping: true, canceled: true, stops: true},
		{name: "wrong grant", op: "revoke", id: "other", wantErr: "授权已结束"},
		{name: "already stopping", op: "revoke", id: "current", stopping: true, stops: true, wantErr: "授权已结束"},
		{name: "expired lease", op: "revoke", id: "current", canceled: true, wantErr: "授权已结束"},
		{name: "revoke current", op: "revoke", id: "current", stops: true},
		{name: "unknown operation", op: "unknown", id: "current", wantErr: "未知的本机操作"},
		{name: "approval only on host", role: "control", phase: "waiting", op: "approve", id: "current", answer: &answer, wantErr: "无法再次批准"},
		{name: "no repeat approval", role: "host", phase: "connecting", op: "approve", id: "current", answer: &answer, wantErr: "无法再次批准"},
		{name: "missing reply", role: "host", phase: "waiting", op: "approve", id: "current", wantErr: "无法再次批准"},
		{name: "scoped access required", role: "host", phase: "waiting", op: "approve", id: "current", answer: &answer, scoped: true, wantErr: "临时 SSH"},
		{name: "approve exactly once", role: "host", phase: "waiting", op: "approve", id: "current", answer: &answer, approves: true},
		{name: "host cannot open controller link", role: "host", phase: "ready", op: "link", id: "current", wantErr: "尚未建立"},
		{name: "link needs ready grant", role: "control", phase: "waiting", op: "link", id: "current", wantErr: "尚未建立"},
		{name: "link needs live peer", role: "control", phase: "ready", op: "link", id: "current", wantErr: "尚未建立"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			w := &worker{state: State{PairingCode: fixtureCode, ID: "current", Role: tc.role, Phase: tc.phase, RequireScoped: tc.scoped}, offer: offer,
				approval: make(chan grant.Ticket, 1), stopping: tc.stopping}
			state, _, _, err := w.acceptRequest(ctx, request{ID: tc.id, Op: tc.op, Answer: tc.answer}, now)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("got %v; want %q", err, tc.wantErr)
			}
			if state.ID != "current" || w.stopping != tc.stops {
				t.Fatalf("state=%+v stopping=%v", state, w.stopping)
			}
			wantPhase := tc.phase
			select {
			case got := <-w.approval:
				if !tc.approves || !bytes.Equal(got.Signature, answer.Signature) {
					t.Fatal("wrong approval delivered")
				}
				wantPhase = "connecting"
			default:
				if tc.approves {
					t.Fatal("approval did not reach worker")
				}
			}
			if w.state.Phase != wantPhase {
				t.Fatalf("phase = %q, want %q", w.state.Phase, wantPhase)
			}
		})
	}
}

func TestWorkerLinkSlotsAndLifetime(t *testing.T) {
	w := &worker{}
	w.resetLinks(t.Context())
	old := w.linkCtx
	w.resetLinks(t.Context())
	if old.Err() != context.Canceled || w.linkCtx.Err() != nil {
		t.Fatal("reset did not cancel only the old link generation")
	}
	for i := 0; i < 32; i++ {
		if !w.enter() {
			t.Fatalf("slot %d was incorrectly rejected", i)
		}
	}
	if w.enter() {
		t.Fatal("terminal limit was not enforced")
	}
	w.leave()
	if !w.enter() {
		t.Fatal("released terminal slot not reused")
	}
	w.stopping = true
	w.leave()
	if w.enter() {
		t.Fatal("stopping worker admitted a terminal")
	}
	for i := 0; i < 31; i++ {
		w.leave()
	}
	w.links.Wait()
	if w.snapshot().Terminals != 0 {
		t.Fatal("terminal count did not drain")
	}
}

func TestGrantRecoveryResetsOutageWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ticks := make(chan time.Time)
	remote := make(chan error, 1)
	done := make(chan error, 1)
	events := make(chan string, 8)
	checked := make(chan struct{})
	var connected atomic.Bool
	go func() {
		done <- waitForGrantEndEvents(ctx, ctx, func() bool {
			v := connected.Load()
			checked <- struct{}{}
			return v
		}, remote, ticks,
			func() { events <- "close stalled" },
			func(prolonged bool) {
				if prolonged {
					events <- "warn"
				} else {
					events <- "clear"
				}
			})
	}()
	base := time.Now()
	step := func(d time.Duration, up bool) {
		t.Helper()
		connected.Store(up)
		select {
		case ticks <- base.Add(d):
		case <-ctx.Done():
			t.Fatal("worker did not read tick")
		}
		select {
		case <-checked:
		case <-ctx.Done():
			t.Fatal("worker did not check route")
		}
	}
	expect := func(want string) {
		t.Helper()
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		case <-ctx.Done():
			t.Fatalf("missing %q", want)
		}
	}
	step(0, false)
	step(routeRecoveryWindow-time.Second, false)
	step(routeRecoveryWindow, false)
	expect("close stalled")
	step(prolongedOutageWindow, false)
	expect("warn")
	step(prolongedOutageWindow+time.Second, true)
	expect("clear")
	step(2*prolongedOutageWindow, false)
	step(2*prolongedOutageWindow+routeRecoveryWindow, false)
	expect("close stalled")
	want := errors.New("remote transport ended")
	remote <- want
	select {
	case got := <-done:
		if !errors.Is(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	case <-ctx.Done():
		t.Fatal("remote closure did not end wait")
	}
	if len(events) != 0 {
		t.Fatalf("unexpected route events: %d", len(events))
	}
}

func TestServeRejectsInvalidStartupBeforeNetwork(t *testing.T) {
	key := filepath.Join(t.TempDir(), "identity")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"relative key", Options{Key: "device"}, "完整路径"},
		{"uninitialized profile", Options{Key: key + ".absent"}, "未知授权角色"},
		{"unknown role", Options{Key: key, Role: "unknown"}, "未知授权角色"},
		{"zero ttl", Options{Key: key, Role: "host", Port: 22}, "授权时长"},
		{"long ttl", Options{Key: key, Role: "host", Port: 22, TTL: grant.MaxTTL + time.Second}, "授权时长"},
		{"zero port", Options{Key: key, Role: "host", TTL: time.Minute}, "SSH 端口"},
		{"port overflow", Options{Key: key, Role: "host", Port: 65536, TTL: time.Minute}, "SSH 端口"},
		{"scoped wrong port", Options{Key: key, Role: "host", Port: 2222, TTL: time.Minute, RequireScoped: true}, "SSH 端口"},
		{"legacy offer", Options{Key: key, Role: "control"}, "重新配对"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var in, out bytes.Buffer
			if err := send(&in, tc.opts); err != nil {
				t.Fatal(err)
			}
			err := Serve(t.Context(), &in, &out)
			matches := err != nil && strings.Contains(err.Error(), tc.want)
			if tc.name == "missing key" {
				matches = errors.Is(err, os.ErrNotExist)
			}
			if !matches || out.Len() != 0 {
				t.Fatalf("serve=%v output=%q", err, out.String())
			}
		})
	}
	if err := Serve(t.Context(), bytes.NewReader(nil), io.Discard); !errors.Is(err, io.EOF) {
		t.Fatalf("empty startup=%v", err)
	}
}

func TestServeCleansBootstrapStateWhenReadyCannotBeDelivered(t *testing.T) {
	for _, tc := range []string{"closed readiness writer", "discovery destination is a directory"} {
		t.Run(tc, func(t *testing.T) {
			root := t.TempDir()
			key := filepath.Join(root, "device.key")
			if _, err := grant.NewIdentity(key); err != nil {
				t.Fatal(err)
			}
			scratch := t.TempDir()
			t.Setenv("TMPDIR", scratch)
			t.Setenv("TEMP", scratch)
			t.Setenv("TMP", scratch)
			discovery := key + ".active"
			var out io.Writer = &failedFrameWriter{}
			if tc == "discovery destination is a directory" {
				if err := os.Mkdir(discovery, 0700); err != nil {
					t.Fatal(err)
				}
				out = io.Discard
			}
			var in bytes.Buffer
			if err := send(&in, Options{Role: "host", Key: key, TTL: time.Minute, Port: 2222, STUN: "none"}); err != nil {
				t.Fatal(err)
			}
			if err := Serve(t.Context(), &in, out); err == nil {
				t.Fatal("worker reported success despite undeliverable bootstrap")
			}
			lease, err := grant.LeaseIdentity(key)
			if err != nil {
				t.Fatalf("failed bootstrap retained identity lease: %v", err)
			}
			lease.Close()
			info, err := os.Stat(discovery)
			if tc == "closed readiness writer" && !errors.Is(err, os.ErrNotExist) ||
				tc != "closed readiness writer" && (err != nil || !info.IsDir()) {
				t.Fatalf("failed startup altered discovery path unexpectedly: %v / %v", info, err)
			}
			files, err := filepath.Glob(filepath.Join(scratch, "peertty-grant-*"))
			if err != nil || len(files) != 0 {
				t.Fatalf("scratch not cleaned: %v / %v", files, err)
			}
		})
	}
}

func TestControlBootstrapValidatesHostBeforeClaimingIdentity(t *testing.T) {
	key := filepath.Join(t.TempDir(), "identity")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	self, err := grant.LoadIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, tc := range []struct {
		name     string
		signer   ed25519.PrivateKey
		deadline time.Time
		want     string
	}{
		{"matching old profile does not bypass lease", self, now.Add(time.Minute), grant.ErrInUse.Error()},
		{"valid host offer cannot steal existing lease", host, now.Add(time.Minute), grant.ErrInUse.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			activeLease, err := grant.LeaseIdentity(key)
			if err != nil {
				t.Fatal(err)
			}
			defer activeLease.Close()
			offer, err := grant.NewLoginOffer(tc.signer, "fixture offer", "operator", nil, tc.deadline)
			if err != nil {
				t.Fatal(err)
			}
			if err := fixtureCode.Seal(&offer); err != nil {
				t.Fatal(err)
			}
			var in, out bytes.Buffer
			if err := send(&in, Options{Role: "control", Key: key, Offer: offer, PairingCode: fixtureCode, STUN: "none"}); err != nil {
				t.Fatal(err)
			}
			err = Serve(t.Context(), &in, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) || out.Len() != 0 {
				t.Fatalf("unexpected bootstrap order or publication: %v / %q", err, out.String())
			}
			if _, err := os.Stat(key + ".active"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected start published worker discovery: %v", err)
			}
		})
	}
}

func TestServeReleasesIdentityWhenScratchCannotBeCreated(t *testing.T) {
	root := t.TempDir()
	scratch := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(scratch, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", scratch)
	t.Setenv("TEMP", scratch)
	t.Setenv("TMP", scratch)
	if os.TempDir() != scratch {
		t.Skip("platform did not use isolated scratch fixture")
	}
	key := filepath.Join(root, "identity")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	var in, out bytes.Buffer
	if err := send(&in, Options{Role: "host", Key: key, Port: 2222, TTL: time.Minute, STUN: "none"}); err != nil {
		t.Fatal(err)
	}
	if err := Serve(t.Context(), &in, &out); err == nil || out.Len() != 0 {
		t.Fatalf("worker started without private scratch: %v / %q", err, out.String())
	}
	lease, err := grant.LeaseIdentity(key)
	if err != nil {
		t.Fatalf("bootstrap failure kept identity locked: %v", err)
	}
	defer lease.Close()
	if _, err := os.Stat(key + ".active"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed bootstrap published discovery: %v", err)
	}
}
