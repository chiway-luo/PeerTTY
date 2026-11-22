package active

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"peertty/internal/grant"
)

// Start re-execs the current binary. Stand in for its CLI entry point so the
// real bootstrap pipe and framing are exercised without starting a grant.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == Command && os.Getenv("PEERTTY_ACTIVE_START_FIXTURE") == "1" {
		var opts Options
		if receive(os.Stdin, &opts) != nil {
			os.Exit(2)
		}
		var r reply
		switch opts.Role {
		case "ready":
			r.State = State{ID: opts.Key, Phase: "ready"}
		case "busy":
			r.Error = grant.ErrInUse.Error()
		case "fail":
			r.Error = "fixture startup failure"
		case "truncated":
			os.Stdout.Write([]byte{0, 0})
			os.Exit(0)
		default:
			os.Exit(2)
		}
		if send(os.Stdout, r) != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStartReportsWorkerBootstrapOutcome(t *testing.T) {
	t.Setenv("PEERTTY_ACTIVE_START_FIXTURE", "1")
	for _, role := range []string{"ready", "busy", "fail", "truncated"} {
		t.Run(role, func(t *testing.T) {
			st, err := Start(t.Context(), Options{Role: role, Key: "fixture key with spaces"})
			switch role {
			case "ready":
				if err != nil || st.ID != "fixture key with spaces" || st.Phase != "ready" {
					t.Fatalf("state=%+v err=%v", st, err)
				}
			case "busy":
				if !errors.Is(err, grant.ErrInUse) {
					t.Fatalf("want lease conflict, got %v", err)
				}
			case "fail":
				if err == nil || err.Error() != "fixture startup failure" {
					t.Fatalf("got %v", err)
				}
			case "truncated":
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("got %v", err)
				}
			}
			if err != nil && st != (State{}) {
				t.Fatalf("failed bootstrap exposed %+v", st)
			}
		})
	}
	if _, err := Start(t.Context(), Options{Key: strings.Repeat("x", frameLimit)}); err == nil {
		t.Fatal("oversized bootstrap accepted")
	}
}
