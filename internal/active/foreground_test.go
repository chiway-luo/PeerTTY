package active

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"peertty/internal/grant"
)

func TestForegroundCleanupPreservesReplacementGrant(t *testing.T) {
	key := filepath.Join(t.TempDir(), "profile")
	ctx, cancel, err := grant.WithLifetime(t.Context(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	open := func(role string) *Foreground {
		t.Helper()
		fg, err := ReserveForeground(key, role)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { fg.Close() })
		if err := fg.Publish(ctx, cancel); err != nil {
			t.Fatal(err)
		}
		return fg
	}
	first := open("host")
	if err := first.Publish(ctx, cancel); !errors.Is(err, grant.ErrInUse) {
		t.Fatal("published two endpoints for one lease", err)
	}
	first.Progress("waiting", "", "")
	st, err := Status(ctx, key)
	if err != nil || st.Phase != "waiting" || !st.OneShot || st.Remaining == nil {
		t.Fatal("foreground status missing the enforced lifetime", err)
	}
	if err := Approve(ctx, key, st.ID, grant.Ticket{}); err == nil || err.Error() != ErrOneShot.Error() {
		t.Fatal("file exchange accepted menu approval", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next := open("control")
	next.Progress("ready", "fixture", "udp")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Publish(ctx, cancel); !errors.Is(err, ErrInactive) {
		t.Fatal("closed foreground owner published again", err)
	}
	if err := Revoke(ctx, key, st.ID); err == nil {
		t.Fatal("stale revoke ended the replacement")
	}
	replacement, err := Status(ctx, key)
	if err != nil || replacement.ID == st.ID || replacement.Terminals != 1 || replacement.Route != "udp" || ctx.Err() != nil {
		t.Fatal("old owner disrupted the new session", err)
	}
}
