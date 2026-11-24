package console

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestHostPanelRefreshesSameGrantThroughNetworkChange(t *testing.T) {
	_, owner, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	offer, err := grant.NewLoginOffer(owner, "fixture offer", "robot", nil, deadline)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "offer")
	if err := offer.WriteNew(path); err != nil {
		t.Fatal(err)
	}
	st := active.State{ID: "original", Role: "host", Phase: "gathering", Deadline: deadline}
	updates := []active.State{
		{ID: st.ID, Role: st.Role, Deadline: deadline, Phase: "waiting", Exchange: path},
		{ID: st.ID, Role: st.Role, Deadline: deadline, Phase: "connecting", Note: "checking route"},
		{ID: st.ID, Role: st.Role, Deadline: deadline, Phase: "ready", Route: "fixture original route"},
		{ID: st.ID, Role: st.Role, Deadline: deadline, Phase: "disconnected", Note: "fixture network switched"},
		{ID: st.ID, Role: st.Role, Deadline: deadline, Phase: "disconnected", Note: "fixture still waiting"},
		{ID: st.ID, Role: st.Role, Deadline: deadline, Phase: "ready", Route: "fixture recovered route"},
		{ID: "replacement", Role: st.Role, Deadline: deadline, Phase: "ready", Route: "unexpected replacement"},
	}
	for _, full := range []bool{false, true} {
		name := "linear"
		if full {
			name = "full screen"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			var log bytes.Buffer
			pending := make(chan line)
			c := Console{out: &log, fullScreen: full, pending: pending, Settings: Settings{KeyPath: filepath.Join(dir, "identity")}}
			calls := 0
			svc := hostPanelServices{
				status: func(_ context.Context, path string) (active.State, error) {
					if path != c.KeyPath || calls >= len(updates) {
						t.Fatalf("unexpected status poll: %q, %d", path, calls)
					}
					s := updates[calls]
					calls++
					return s, nil
				},
				revoke: func(context.Context, string, string) error { t.Fatal("route update attempted revocation"); return nil },
				approve: func(context.Context, string, string, grant.Ticket) error {
					t.Fatal("route update attempted approval")
					return nil
				},
			}
			err := c.hostPanel(ctx, st, reconnectTicks(1), reconnectTicks(len(updates)-1), svc)
			if err != nil || calls != len(updates) || c.pending != pending || c.activity != "" {
				t.Fatalf("host refresh lost state: err=%v calls=%d pending=%v activity=%q", err, calls, c.pending, c.activity)
			}
			events := []string{"正在收集直连地址", "将邀请私发给对方", "checking route", "fixture original route", "fixture network switched", "fixture still waiting", "fixture recovered route", "被控会话已结束"}
			rest := log.String()
			for _, event := range events {
				_, later, ok := strings.Cut(rest, event)
				if !ok {
					t.Fatalf("event %q missing or out of order: %q", event, log.String())
				}
				rest = later
			}
			if strings.Contains(log.String(), "unexpected replacement") {
				t.Fatal("panel followed replacement grant")
			}
		})
	}
}

func TestHostPanelReportsStatusFailureAfterConnection(t *testing.T) {
	var out bytes.Buffer
	c := Console{out: &out, pending: make(chan line)}
	st := active.State{ID: "original", Role: "host", Phase: "ready", Deadline: time.Now().Add(time.Minute)}
	want := errors.New("fixture status unavailable")
	err := c.hostPanel(t.Context(), st, nil, reconnectTicks(1), hostPanelServices{
		status: func(context.Context, string) (active.State, error) { return active.State{}, want },
	})
	if !errors.Is(err, want) || strings.Contains(out.String(), "被控会话已结束") {
		t.Fatalf("transient status failure incorrectly reported as ended: %v / %q", err, out.String())
	}
}
