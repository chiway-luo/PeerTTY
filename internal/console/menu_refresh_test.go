package console

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"peertty/internal/active"
)

func TestMenuRefreshPreservesPendingInputAcrossGrantChanges(t *testing.T) {
	for _, tc := range []struct{ phase, ending string }{
		{"ready", "授权已结束。"},
		{"disconnected", "直连已断开，本次授权已结束。请双方重新配对。"},
		{"offline", "直连已断开，本次授权已结束。请双方重新配对。"},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var out bytes.Buffer
				entry := make(chan line)
				c := &Console{out: &out, pending: entry, fullScreen: true, Settings: Settings{KeyPath: "fixture.key"}}
				st := active.State{ID: "fixture", Role: "control", Phase: tc.phase}
				updates := []struct {
					state active.State
					err   error
				}{
					{st, nil},
					{active.State{}, errors.New("temporary fixture status failure")},
					{active.State{}, active.ErrInactive},
					{active.State{ID: "replacement", Role: "control", Phase: "connecting"}, nil},
					{active.State{ID: "replacement", Role: "control", Phase: "connecting"}, nil},
				}
				calls := 0
				observedPath := ""
				done := make(chan line, 1)
				go func() {
					got, err := c.menuChoiceWith(t.Context(), statusPage, func(_ context.Context, path string) (active.State, error) {
						observedPath = path
						i := min(calls, len(updates)-1)
						calls++
						return updates[i].state, updates[i].err
					})
					done <- line{text: got, err: err}
				}()
				synctest.Wait()
				time.Sleep(4 * time.Second)
				synctest.Wait()
				entry <- line{text: "/status"}
				got := <-done
				if got.err != nil || got.text != "/status" || c.pending != nil || c.activity != "" {
					t.Fatalf("pending input or terminal activity lost: %+v", got)
				}
				if calls != 5 || observedPath != "fixture.key" {
					t.Fatalf("unexpected refresh count or path: %d/%q", calls, observedPath)
				}
				log := out.String()
				if strings.Contains(log, "temporary fixture status failure") || strings.Count(log, tc.ending) != 1 ||
					!strings.Contains(log, "正在建立直连") {
					t.Fatalf("expected one closure notice and a new connecting page, got %q", log)
				}
			})
		})
	}
}

func TestHelpPageDoesNotPollGrantOnRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out bytes.Buffer
		entry := make(chan line)
		c := &Console{out: &out, pending: entry, interactive: true}
		done := make(chan line, 1)
		calls := 0
		go func() {
			got, err := c.menuChoiceWith(t.Context(), helpPage, func(context.Context, string) (active.State, error) {
				calls++
				return active.State{}, active.ErrInactive
			})
			done <- line{text: got, err: err}
		}()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		entry <- line{text: "/back"}
		if got := <-done; got.err != nil || got.text != "/back" || calls != 0 {
			t.Fatalf("help consumed unexpected input or queried grant: %+v/%d", got, calls)
		}
	})
}
