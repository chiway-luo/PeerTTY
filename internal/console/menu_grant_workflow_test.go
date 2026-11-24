package console

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestMenuRevokeKeepsOriginalReconnectingGrantEvenIfStatusChanges(t *testing.T) {
	cleanupErr := errors.New("fixture authorization cleanup pending")
	for _, revokeErr := range []error{nil, cleanupErr} {
		in, out := sshMenuInput(t, "/link\n/revoke\n/quit\n")
		key := filepath.Join(t.TempDir(), "identity")
		c := &Console{Settings: Settings{KeyPath: key}, in: in, out: out}
		st := active.State{Role: "control", ID: "original", Phase: "disconnected"}
		polls, links, revocations := 0, 0, 0
		err := c.menuWithGrantActions(t.Context(), menuGrantActions{
			status: func(_ context.Context, path string) (active.State, error) {
				polls++
				if path != key {
					t.Fatalf("wrong identity %q", path)
				}
				if polls > 2 {
					return active.State{Role: "control", ID: "replacement", Phase: "ready"}, nil
				}
				return st, nil
			},
			link: func(_ context.Context, selected active.State) error {
				links++
				if selected != st {
					t.Fatalf("unexpected link state %+v", selected)
				}
				return reconnectingGrant{id: selected.ID}
			},
			revoke: func(_ context.Context, path, id string) error {
				revocations++
				if path != key || id != st.ID || polls != 3 {
					t.Fatalf("revoke targeted replacement after refresh: %q / %q / polls %d", path, id, polls)
				}
				return revokeErr
			},
		})
		if err != nil || links != 1 || revocations != 1 {
			t.Fatalf("unexpected command lifecycle: %v, links=%d revokes=%d", err, links, revocations)
		}
		log := out.String()
		if strings.Contains(log, "本次授权已撤销") != (revokeErr == nil) ||
			strings.Contains(log, cleanupErr.Error()) != (revokeErr != nil) {
			t.Fatalf("revocation message inconsistent with actual result: %q", log)
		}
	}
}

func TestMenuDispatchesActiveReceiptWithoutLaunchingNewControl(t *testing.T) {
	for _, tc := range []struct {
		command, role, wantMessage string
		review                     bool
		wantedError                error
	}{
		{command: "/connect", role: "control"},
		{command: "/receipt", role: "control", review: true},
		{command: "/receipt", role: "host", wantMessage: "请在本次授权的控制端查看回执"},
		{command: "/connect", role: "host", wantMessage: grant.ErrInUse.Error()},
		{command: "/connect", role: "host", wantedError: errNewWindow},
	} {
		in, out := sshMenuInput(t, tc.command+"\n/quit\n")
		c := &Console{in: in, out: out}
		s := active.State{ID: "selected", Role: tc.role, Phase: "waiting"}
		panels, controls := 0, 0
		err := c.menuWithGrantActions(t.Context(), menuGrantActions{
			status: func(context.Context, string) (active.State, error) { return s, nil },
			panel: func(_ context.Context, selected active.State, text, review bool) error {
				panels++
				if selected != s || text || review != tc.review {
					t.Fatalf("opened wrong panel policy: %+v, text=%v review=%v", selected, text, review)
				}
				return errBack
			},
			control: func(_ context.Context, invitation string) error {
				controls++
				if invitation != "" {
					t.Fatalf("unexpected invitation: %q", invitation)
				}
				if tc.wantedError != nil {
					return tc.wantedError
				}
				return grant.ErrInUse
			},
		})
		if !errors.Is(err, tc.wantedError) || (panels == 1) != (tc.role == "control") || (controls == 1) != (tc.command == "/connect" && tc.role == "host") ||
			!strings.Contains(out.String(), tc.wantMessage) {
			t.Fatalf("wrong dispatch for %s/%s: %v / panels=%d / controls=%d / %q", tc.command, tc.role, err, panels, controls, out.String())
		}
	}
}

func TestMenuDirectInvitationAndEOFStayWithinCurrentInteraction(t *testing.T) {
	for _, entry := range []string{`{"claims":{}}`, "/paste"} {
		in, out := sshMenuInput(t, entry+"\n")
		c := &Console{in: in, out: out}
		var calls int
		err := c.menuWithGrantActions(t.Context(), menuGrantActions{
			status: func(context.Context, string) (active.State, error) { return active.State{}, active.ErrInactive },
			control: func(_ context.Context, got string) error {
				calls++
				if got != entry || c.section != connectAction.title {
					t.Fatalf("menu altered invitation or command: %q / %q", got, c.section)
				}
				return io.EOF
			},
		})
		if err != nil || calls != 1 || strings.Contains(out.String(), "操作结束") {
			t.Fatalf("input EOF was treated as failed operation: %v / %d / %q", err, calls, out.String())
		}
	}
}
