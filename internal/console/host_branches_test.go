package console

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

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/localssh"
)

func hostPanelInput(t *testing.T, input string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "terminal-input")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	return in
}

func TestHostPanelApprovalAndRevocation(t *testing.T) {
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	loginPub, operator, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	hostPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	offer, err := grant.NewLoginOffer(host, "test description", "robot", hostPub, deadline)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "offer")
	if err := offer.WriteNew(path); err != nil {
		t.Fatal(err)
	}
	standard, scoped := filepath.Join(dir, "standard"), filepath.Join(dir, "scoped")
	for _, variant := range []struct {
		path string
		key  ed25519.PublicKey
	}{{standard, nil}, {scoped, loginPub}} {
		reply, err := grant.NewLoginAnswer(operator, offer, "reply description", variant.key)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixtureCode.Seal(&reply); err != nil {
			t.Fatal(err)
		}
		if err := reply.WriteNew(variant.path); err != nil {
			t.Fatal(err)
		}
	}

	keyPath := filepath.Join(dir, "host-id")
	readErr := errors.New("status read failed")
	actionErr := errors.New("grant action failed")
	for _, tc := range []struct {
		name, phase, input, note  string
		requireScoped, failAction bool
		approve, revoke           int
		err                       error
		wants                     []string
	}{
		{name: "scoped then revoke", phase: "waiting", input: "\n" + standard + "\n" + scoped + "\ny\nq\n", requireScoped: true, approve: 1, revoke: 1,
			wants: []string{"回执无效，可重新输入", "批准后可直接登录当前账号 robot", "本次授权已撤销"}},
		{name: "discard selected reply", phase: "waiting", input: standard + "\nr\ny\nb\n", err: errBack,
			wants: []string{"每次登录使用被控机的系统 SSH 认证", "授权继续有效"}},
		{name: "approval failure", phase: "waiting", input: standard + "\ny\n", approve: 1, failAction: true, err: actionErr},
		{name: "ready with notice", phase: "ready", input: "v\n{}\n/back\n", note: "record diagnostic", err: errBack,
			wants: []string{"被控会话已连接", "record diagnostic", "无法更换回执"}},
		{name: "revoke during reconnect", phase: "disconnected", input: "/revoke\n", revoke: 1, wants: []string{"正在重连", "本次授权已撤销"}},
		{name: "failed revoke leaves guidance", phase: "disconnected", input: "q\n", revoke: 1, failAction: true, err: actionErr},
		{name: "end of input", phase: "ready", err: io.EOF},
		{name: "offline", phase: "offline", note: "disconnected diagnostic", err: errors.New("disconnected diagnostic")},
		{name: "gather and status failure", phase: "gathering", err: readErr, wants: []string{"正在收集直连地址"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			var out bytes.Buffer
			c := Console{Settings: Settings{KeyPath: keyPath}, out: &out, in: hostPanelInput(t, tc.input)}
			st := active.State{PairingCode: fixtureCode, ID: "chosen", Role: "host", Phase: tc.phase, Deadline: deadline, Exchange: path, Note: tc.note, RequireScoped: tc.requireScoped}
			var approved, revoked int
			deps := hostPanelServices{
				status: func(_ context.Context, path string) (active.State, error) {
					if path != keyPath {
						t.Fatalf("wrong status key: %q", path)
					}
					return active.State{}, readErr
				},
				approve: func(_ context.Context, path, id string, ans grant.Ticket) error {
					approved++
					if path != keyPath || id != st.ID || st.CheckAnswer(offer, ans, time.Now()) != nil {
						t.Fatal("forwarded an unverified authorization")
					}
					if tc.failAction {
						return actionErr
					}
					return nil
				},
				revoke: func(_ context.Context, path, id string) error {
					revoked++
					if path != keyPath || id != st.ID {
						t.Fatal("revoked wrong authorization")
					}
					if tc.failAction {
						return actionErr
					}
					return nil
				},
			}
			var spin <-chan time.Time
			if tc.phase == "gathering" {
				spin = reconnectTicks(1)
			}
			got := c.hostPanel(ctx, st, spin, nil, deps)
			if tc.phase == "offline" {
				if got == nil || got.Error() != tc.err.Error() {
					t.Fatalf("offline error = %v, want %v", got, tc.err)
				}
			} else if !errors.Is(got, tc.err) {
				t.Fatalf("error = %v, want %v; %q", got, tc.err, out.String())
			}
			if approved != tc.approve || revoked != tc.revoke {
				t.Fatalf("actions = approve %d revoke %d", approved, revoked)
			}
			for _, sub := range tc.wants {
				if !strings.Contains(out.String(), sub) {
					t.Fatalf("missing %q in %q", sub, out.String())
				}
			}
		})
	}
}

func TestHostDurationInputRespectsBounds(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        time.Duration
		err         error
		retry       bool
	}{
		{"default", "\n", time.Hour, nil, false},
		{"cancel", "Q\n", 0, errBack, false},
		{"input closed", "", 0, io.EOF, false},
		{"largest hours", "24\n", 24 * time.Hour, nil, false},
		{"minutes", "30m\n", 30 * time.Minute, nil, false},
		{"invalid then minimum", "0\n25\n0s\n24h1m\n1m\n", time.Minute, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			ui := Console{Settings: Settings{TTL: time.Hour}, in: hostPanelInput(t, tc.input), out: &log}
			got, err := ui.askDuration(t.Context(), localssh.Check{})
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("duration=%s (%v), want %s (%v)", got, err, tc.want, tc.err)
			}
			if tc.retry != strings.Contains(log.String(), "请输入 1 到 24") {
				t.Fatalf("unexpected retry output %q", log.String())
			}
		})
	}
}

func TestHostPanelDoesNotFollowReplacementGrant(t *testing.T) {
	var log bytes.Buffer
	ui := Console{Settings: Settings{KeyPath: filepath.Join(t.TempDir(), "identity")}, out: &log}
	st := active.State{ID: "old", Role: "host", Phase: "gathering", Deadline: time.Now().Add(time.Minute)}
	poll := reconnectTicks(1)
	var calls int
	services := hostPanelServices{
		status: func(context.Context, string) (active.State, error) {
			calls++
			return active.State{ID: "replacement", Role: "host", Phase: "ready"}, nil
		},
	}
	if err := ui.hostPanel(t.Context(), st, reconnectTicks(1), poll, services); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !strings.Contains(log.String(), "被控会话已结束") || strings.Contains(log.String(), "被控会话已连接") {
		t.Fatalf("followed a replacement: calls=%d; %q", calls, log.String())
	}
}
