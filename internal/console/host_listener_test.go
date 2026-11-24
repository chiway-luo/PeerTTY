package console

import (
	"context"
	"slices"
	"testing"
	"time"

	"peertty/internal/localssh"
)

func TestListenerWatchReportsChangesAndRechecksEvenWithoutVacancy(t *testing.T) {
	for _, tc := range []struct {
		name string
		port int
	}{{"standard", 22}, {"custom", 2222}} {
		t.Run(tc.name, func(t *testing.T) {
			port := tc.port
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			now := time.Now()
			ticks := make(chan time.Time, 7)
			for _, seconds := range []int{2, 12, 14, 16, 18, 30, 42} {
				ticks <- now.Add(time.Duration(seconds) * time.Second)
			}
			var vacancyChecks, factories, probes int
			updates := make(chan localssh.Check, 4)
			active := localssh.Check{Ready: true, Message: "ready"}
			closed := localssh.Check{Closed: true, Message: "closed"}
			newStatus := localssh.Check{Message: "awaiting"}
			vacancy := func() bool {
				vacancyChecks++
				return vacancyChecks == 2
			}
			watchListenerEvents(ctx, port, active, vacancy,
				func(gotPort int) func() bool {
					factories++
					if gotPort != port {
						t.Fatalf("factory got port %d", gotPort)
					}
					return vacancy
				},
				func(_ context.Context, gotPort int) localssh.Check {
					probes++
					if gotPort != port {
						t.Fatalf("probe got port %d", gotPort)
					}
					switch probes {
					case 1:
						return active
					case 2, 3:
						return closed
					case 4:
						return active
					case 5:
						return newStatus
					default:
						cancel()
						return newStatus
					}
				}, now, ticks, updates)
			if vacancyChecks != 2 || factories != 1 || probes != 6 {
				t.Fatalf("vacancy checks=%d factories=%d probes=%d", vacancyChecks, factories, probes)
			}
			close(updates)
			var labels []string
			for st := range updates {
				labels = append(labels, st.Message)
			}
			wantClosed := closed.Message
			if port == 22 {
				wantClosed = "本机 22 端口已关闭，提交授权时长后将复查临时 SSH。"
			}
			if !slices.Equal(labels, []string{wantClosed, active.Message, newStatus.Message}) {
				t.Fatalf("duplicate or missing listener changes: %q", labels)
			}
		})
	}
}

func TestListenerWatchCancellationDoesNotBlockPendingUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	calls := 0
	watchListenerEvents(ctx, 22, localssh.Check{Closed: true}, nil, func(int) func() bool { return nil },
		func(context.Context, int) localssh.Check {
			calls++
			cancel()
			return localssh.Check{Ready: true, Message: "ready"}
		}, time.Now(), reconnectTicks(1), make(chan localssh.Check))
	if calls != 1 {
		t.Fatalf("unexpected number of probes: %d", calls)
	}
}
