package console

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
)

func reconnectTicks(n int) <-chan time.Time {
	ticks := make(chan time.Time, n)
	for i := 0; i < n; i++ {
		ticks <- time.Now()
	}
	return ticks
}

func TestWaitReconnectUsesOnlyOriginalGrant(t *testing.T) {
	old := active.State{ID: "original", Role: "control", Phase: "disconnected", Deadline: time.Now().Add(time.Minute)}
	for _, tc := range []struct {
		name, id, phase string
		err             error
	}{
		{"recovered", old.ID, "ready", nil},
		{"replacement", "another", "ready", nil},
		{"failed route", old.ID, "offline", nil},
		{"revoked", "", "", active.ErrInactive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			var calls int
			st, err := waitReconnect(t.Context(), old, &log, reconnectTicks(2), func(context.Context) (active.State, error) {
				calls++
				if calls == 1 {
					return old, nil
				}
				return active.State{ID: tc.id, Role: old.Role, Phase: tc.phase}, tc.err
			})
			ok := tc.name == "recovered"
			if (err == nil) != ok || (st.ID == old.ID) != ok || (tc.err != nil && !errors.Is(err, tc.err)) {
				t.Fatalf("unexpected state/error: %+v / %v", st, err)
			}
			if strings.Count(log.String(), "正在重连") != 1 || strings.Contains(log.String(), "直连已恢复") != ok || calls != 2 {
				t.Fatalf("unexpected output %q, calls=%d", log.String(), calls)
			}
		})
	}
	old.Deadline = time.Now().Add(-time.Second)
	_, err := waitReconnect(t.Context(), old, &bytes.Buffer{}, nil, func(context.Context) (active.State, error) {
		t.Fatal("expired grant was checked again")
		return active.State{}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired grant: %v", err)
	}
}

func TestWatchSSHConnectionShowsTransitionsOnce(t *testing.T) {
	var log bytes.Buffer
	phases := []string{"ready", "disconnected", "disconnected", "ready", "disconnected", "offline"}
	i := 0
	watchSSHConnection(t.Context(), "selected", &log, reconnectTicks(len(phases)), func(context.Context) (active.State, error) {
		s := active.State{ID: "selected", Phase: phases[i]}
		i++
		return s, nil
	})
	message := "\r\n" + reconnectNotice + "\r\n" + reconnectRevokeHint + "\r\n"
	if got, want := log.String(), message+"\r\n直连已恢复。\r\n"+message+"\r\n直连未恢复，请重新配对。\r\n"; got != want {
		t.Fatalf("transcript = %q, want %q", got, want)
	}
}

func TestReconnectMenuKeepsRevokeAvailable(t *testing.T) {
	st := active.State{ID: "selected", Role: "control", Phase: "disconnected", Deadline: time.Now().Add(time.Minute)}
	c := Console{out: &bytes.Buffer{}}
	for _, show := range []func() error{
		func() error { return c.waitControl(t.Context(), st, false) },
		func() error { return c.linkSSH(t.Context(), st) },
	} {
		var pending reconnectingGrant
		if err := show(); !errors.As(err, &pending) || pending.id != st.ID {
			t.Fatalf("menu should return to status for grant %q: %v", st.ID, err)
		}
	}
	for _, fullScreen := range []bool{false, true} {
		log := &bytes.Buffer{}
		c.out, c.fullScreen = log, fullScreen
		c.drawMenu(terminalView{width: 80, height: 24}, statusPage, st, nil)
		if got := log.String(); !strings.Contains(got, "正在重连") || !strings.Contains(got, "/revoke") {
			t.Fatalf("missing revoke during reconnect: %q", got)
		}
	}
}

func TestWatchSSHConnectionSurvivesStatusReadError(t *testing.T) {
	var log bytes.Buffer
	steps := []struct {
		state active.State
		err   error
	}{
		{state: active.State{ID: "selected", Phase: "disconnected"}},
		{err: errors.New("status temporarily unavailable")},
		{state: active.State{ID: "selected", Phase: "disconnected"}},
		{state: active.State{ID: "selected", Phase: "ready"}},
		{err: active.ErrInactive},
	}
	i := 0
	watchSSHConnection(t.Context(), "selected", &log, reconnectTicks(len(steps)), func(context.Context) (active.State, error) {
		step := steps[i]
		i++
		return step.state, step.err
	})
	want := "\r\n" + reconnectNotice + "\r\n" + reconnectRevokeHint + "\r\n\r\n直连已恢复。\r\n\r\nSSH 会话已断开，本次授权已结束。\r\n"
	if i != len(steps) || log.String() != want {
		t.Fatalf("calls=%d, transcript=%q, want %q", i, log.String(), want)
	}
}

func TestWatchSSHConnectionStopsBeforeLateRecovery(t *testing.T) {
	for _, reason := range []string{"replacement", "cancellation"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var log bytes.Buffer
			i := 0
			watchSSHConnection(ctx, "selected", &log, reconnectTicks(3), func(context.Context) (active.State, error) {
				i++
				switch i {
				case 1:
					return active.State{ID: "selected", Phase: "disconnected"}, nil
				case 2:
					if reason == "cancellation" {
						cancel()
						return active.State{ID: "selected", Phase: "ready"}, nil
					}
					return active.State{ID: "next", Phase: "ready"}, nil
				default:
					t.Fatal("observed a stale grant after stop")
					return active.State{}, active.ErrInactive
				}
			})
			want := "\r\n" + reconnectNotice + "\r\n" + reconnectRevokeHint + "\r\n"
			if reason == "replacement" {
				want += "\r\nSSH 会话已断开，本次授权已结束。\r\n"
			}
			if i != 2 || log.String() != want {
				t.Fatalf("calls=%d, transcript=%q, want %q", i, log.String(), want)
			}
		})
	}
}

func TestWaitReconnectRejectsWrongRoleOrLateSuccess(t *testing.T) {
	old := active.State{ID: "selected", Role: "control", Phase: "disconnected", Deadline: time.Now().Add(time.Minute)}
	for _, tc := range []struct {
		name, role string
		cancel     bool
	}{
		{"wrong role", "host", false},
		{"canceled during status lookup", "control", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var log bytes.Buffer
			st, err := waitReconnect(ctx, old, &log, reconnectTicks(1), func(context.Context) (active.State, error) {
				if tc.cancel {
					cancel()
				}
				return active.State{ID: old.ID, Phase: "ready", Role: tc.role}, nil
			})
			if st.ID != "" || err == nil || strings.Contains(log.String(), "直连已恢复") {
				t.Fatalf("reported a late or wrong-role session: %+v %v %q", st, err, log.String())
			}
			if tc.cancel && !errors.Is(err, context.Canceled) || !tc.cancel && !strings.Contains(err.Error(), "授权已结束") {
				t.Fatalf("chose wrong refusal: %v", err)
			}
		})
	}
}

func TestWatchSSHAlreadyCanceledDoesNotQueryStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var diag bytes.Buffer
	watchSSHConnection(ctx, "grant", &diag, nil, func(context.Context) (active.State, error) {
		t.Fatal("status queried after cancellation")
		return active.State{}, nil
	})
	if diag.Len() != 0 {
		t.Fatalf("misleading canceled status: %q", diag.String())
	}
}
