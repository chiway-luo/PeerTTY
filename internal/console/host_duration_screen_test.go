package console

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/localssh"
)

func TestHostDurationFullScreenKeepsInputWhileListenerChanges(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		label := "accept duration"
		if canceled {
			label = "cancel while editing"
		}
		t.Run(label, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			var out bytes.Buffer
			updates, input := make(chan localssh.Check), make(chan line)
			ui := &Console{fullScreen: true, out: &out, pending: input, Settings: Settings{SSHPort: 2222, TTL: time.Hour}}
			initial := localssh.Check{Closed: true, Message: "fixture listener closed"}
			type subscription struct {
				ctx     context.Context
				port    int
				initial localssh.Check
			}
			started := make(chan subscription, 1)
			type answer struct {
				d time.Duration
				e error
			}
			done := make(chan answer, 1)
			go func() {
				d, e := ui.askDurationWith(ctx, initial, func(watch context.Context, port int, first localssh.Check) <-chan localssh.Check {
					started <- subscription{watch, port, first}
					return updates
				})
				done <- answer{d, e}
			}()
			sub := <-started
			if sub.port != 2222 || sub.initial.Message != initial.Message {
				t.Fatalf("incorrect listener subscription: port %d, initial %+v", sub.port, sub.initial)
			}
			select {
			case updates <- localssh.Check{Ready: true, Message: "fixture listener ready", Detail: "first status line\nextra detail"}:
			case <-ctx.Done():
				t.Fatal("screen did not watch listener")
			}
			if canceled {
				cancel()
			} else {
				select {
				case input <- line{text: "30m"}:
				case <-ctx.Done():
					t.Fatal("listener change lost duration input")
				}
			}
			got := <-done
			if canceled {
				if got.d != 0 || !errors.Is(got.e, context.Canceled) || ui.pending != input {
					t.Fatalf("cancellation did not preserve pending input: %+v", got)
				}
			} else if got.d != 30*time.Minute || got.e != nil || ui.pending != nil {
				t.Fatalf("duration not consumed exactly once: %+v", got)
			}
			log := out.String()
			for _, text := range []string{"\x1b[3;r", "\x1b[r", initial.Message, "fixture listener ready", "first status line"} {
				if !strings.Contains(log, text) {
					t.Fatalf("missing %q in %q", text, log)
				}
			}
			if strings.Contains(log, "extra detail") || sub.ctx.Err() == nil {
				t.Fatal("slow status output overran its reserved rows or subscription leaked")
			}
		})
	}
}

func TestHostDurationFullScreenRedrawsAfterRecoverableInputError(t *testing.T) {
	pending := make(chan line, 1)
	pending <- line{err: incompletePaste}
	var out bytes.Buffer
	ui := Console{in: hostPanelInput(t, "1m\n"), out: &out, fullScreen: true, pending: pending, Settings: Settings{TTL: time.Hour}}
	st := localssh.Check{Message: "fixture listener state"}
	got, err := ui.askDurationWith(t.Context(), st, func(context.Context, int, localssh.Check) <-chan localssh.Check { return nil })
	log := out.String()
	if got != time.Minute || err != nil || strings.Count(log, st.Message) != 2 || !strings.Contains(log, incompletePaste.Error()) {
		t.Fatalf("recoverable error did not redraw state and retry: %v, %v / %q", got, err, log)
	}
}

func TestHostExpiresOnlyAfterLocalReleaseFinishes(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		if canceled {
			cancel()
		}
		var out bytes.Buffer
		key := filepath.Join(t.TempDir(), "fixture.key")
		if _, err := grant.NewIdentity(key); err != nil {
			t.Fatal(err)
		}
		ui := &Console{Settings: Settings{KeyPath: key}, out: &out}
		st := active.State{ID: "fixture-ended", Deadline: time.Now().Add(-time.Minute)}
		err := ui.handleHostEnded(ctx, st, active.ErrInactive)
		cancel()
		if canceled {
			if err == nil || !strings.Contains(err.Error(), "仍在回收") || strings.Contains(out.String(), "授权已到期") {
				t.Fatalf("blocked cleanup incorrectly reported complete: %v / %q", err, out.String())
			}
		} else if err != nil || !strings.Contains(out.String(), "授权已到期") {
			t.Fatalf("inactive authorization did not end as expired: %v / %q", err, out.String())
		}
	}
}
