package console

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestReceiptPanelHandoffHonorsSelectedAuthorization(t *testing.T) {
	answerPath := filepath.Join(t.TempDir(), "fixture.answer")
	answer := grant.Ticket{Claims: grant.Claims{Kind: "answer", Session: "test-session"}}
	if err := answer.WriteNew(answerPath); err != nil {
		t.Fatal(err)
	}
	sshErr := errors.New("session failed")
	statusErr := errors.New("status failed")
	for _, tc := range []struct {
		name, phase, input, after, wanted string
		show, review, interactive, copy   bool
		ticks, polls, links, copies       int
		err                               error
	}{
		{name: "gather until approved", phase: "gathering", after: "ready", ticks: 1, polls: 1, links: 1, wanted: "控制会话已结束"},
		{name: "status endpoint error", phase: "gathering", after: "error", ticks: 1, polls: 1, err: statusErr},
		{name: "replacement is not selected", phase: "gathering", after: "replacement", ticks: 1, polls: 1, wanted: "本次授权已结束"},
		{name: "waiting then approved", phase: "waiting", after: "ready", ticks: 3, polls: 1, links: 1, show: true, wanted: ticketBegin},
		{name: "waiting disconnects", phase: "waiting", after: "disconnected", ticks: 3, polls: 1, wanted: reconnectNotice},
		{name: "waiting failed", phase: "waiting", after: "offline", ticks: 3, polls: 1, wanted: "offline detail"},
		{name: "interactive SSH failure", phase: "ready", interactive: true, links: 1, err: sshErr},
		{name: "interactive SSH done", phase: "ready", interactive: true, links: 1, err: errBack},
		{name: "review right before handoff", phase: "ready", review: true, input: "/link\nfirst SSH input\n", ticks: 1, links: 1, wanted: "已连接 · 回车打开 SSH 终端"},
		{name: "return in disconnected review", phase: "disconnected", review: true, input: "b\n", ticks: 1, err: errBack, wanted: reconnectNotice},
		{name: "copy just once on review", phase: "waiting", review: true, copy: true, input: "unknown\nv\nb\n", ticks: 3, polls: 1, copies: 1, err: errBack, wanted: "输入 c 复制回执"},
		{name: "missing receipt", phase: "waiting", err: os.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out := sshMenuInput(t, tc.input)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			menu := Console{out: out, interactive: tc.interactive, autoCopy: tc.copy}
			if tc.interactive || tc.review {
				menu.in = in
			}
			var polls, links, copies int
			menu.copyToClipboard = func(_ context.Context, _ io.Writer, ticket grant.Ticket) (string, error) {
				copies++
				if ticket.Claims.Session != answer.Claims.Session {
					t.Fatal("copied a different grant's receipt")
				}
				return "已复制测试回执", nil
			}
			st := active.State{ID: "selected", Role: "control", Phase: tc.phase, Exchange: answerPath, Deadline: time.Now().Add(time.Minute)}
			if errors.Is(tc.err, os.ErrNotExist) {
				st.Exchange = filepath.Join(t.TempDir(), "missing")
			}
			services := receiptPanelServices{
				status: func(context.Context, string) (active.State, error) {
					polls++
					fresh := st
					switch tc.after {
					case "error":
						return active.State{}, statusErr
					case "replacement":
						fresh.ID, fresh.Phase = "new", "ready"
					case "offline":
						fresh.Phase, fresh.Note = "offline", "offline detail"
					case "ready", "disconnected":
						fresh.Phase = tc.after
					}
					return fresh, nil
				},
				link: func(_ context.Context, s active.State) error {
					links++
					if s.ID != st.ID || s.Phase != "ready" {
						t.Fatalf("opened wrong session: %+v", s)
					}
					if tc.name == "review right before handoff" {
						text, err := readLine(in)
						if err != nil || text != "first SSH input" {
							t.Fatalf("SSH input not preserved: %q %v", text, err)
						}
					}
					if tc.err == sshErr {
						return sshErr
					}
					return nil
				},
			}
			got := menu.receiptPanel(ctx, st, tc.show, tc.review, reconnectTicks(tc.ticks), services)
			if tc.wanted == "本次授权已结束" || tc.wanted == "offline detail" || tc.wanted == reconnectNotice && tc.after == "disconnected" {
				if got == nil || !strings.Contains(got.Error(), tc.wanted) {
					t.Fatalf("got %v, want %q", got, tc.wanted)
				}
			} else if !errors.Is(got, tc.err) {
				t.Fatalf("got %v, want %v; %q", got, tc.err, out.String())
			} else if tc.wanted != "" && !strings.Contains(out.String(), tc.wanted) {
				t.Fatalf("missing %q: %q", tc.wanted, out.String())
			}
			if polls != tc.polls || links != tc.links || copies != tc.copies {
				t.Fatalf("polls %d/%d, links %d/%d, copies %d/%d", polls, tc.polls, links, tc.links, copies, tc.copies)
			}
		})
	}
}

func TestReceiptPanelReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := Console{out: &bytes.Buffer{}}
	err := c.receiptPanel(ctx, active.State{ID: "a", Phase: "gathering"}, false, false, nil, receiptPanelServices{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
