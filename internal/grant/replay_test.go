package grant

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"peertty/internal/identitystate"
)

func replayInvitation(t *testing.T, expiry time.Time) (Ticket, PairingCode, string) {
	t.Helper()
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	controller, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := NewLoginOffer(host, "test description", "user", nil, expiry)
	if err != nil {
		t.Fatal(err)
	}
	code, err := NewPairingCode()
	if err != nil {
		t.Fatal(err)
	}
	if err = code.Seal(&offer); err != nil {
		t.Fatal(err)
	}
	return offer, code, Fingerprint(controller)
}

func TestSpentAndObservedExpiredOffersStayRejectedAfterClockRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller")
	now := time.Now().Truncate(time.Millisecond)
	first, code, id := replayInvitation(t, now.Add(time.Minute))
	fresh, otherCode, otherID := replayInvitation(t, now.Add(3*time.Hour))
	use := func(c PairingCode, ticket Ticket, controller string) error {
		return c.consumeOffer(path, ticket, ticket.Sender(), controller, now, func() time.Time { return now })
	}
	if err := use(otherCode, first, id); err == nil {
		t.Fatal("wrong proof was allowed to consume an invitation")
	}
	if err := use(code, first, id); err != nil {
		t.Fatal(err)
	}
	if err := use(code, first, id); !errors.Is(err, ErrOfferUsed) {
		t.Fatal("second use", err)
	}
	now = now.Add(time.Hour)
	if err := use(otherCode, fresh, otherID); err != nil {
		t.Fatal("fresh pairing", err)
	}
	// The individual entry has been pruned by a later successful pairing.
	raw, err := os.ReadFile(identitystate.RuntimePath(path, "used-offers.json"))
	if err != nil || bytes.Contains(raw, []byte(first.Claims.Session)) || bytes.Contains(raw, []byte(otherCode)) {
		t.Fatal("unexpected persisted record", err)
	}
	observed, observedCode, observedID := replayInvitation(t, now.Add(-time.Minute))
	if err := use(observedCode, observed, observedID); !errors.Is(err, errTicketLifetime) {
		t.Fatal("first observation of an expired invitation", err)
	}
	now = now.Add(-90 * time.Minute)
	for _, old := range []struct {
		ticket Ticket
		code   PairingCode
		id     string
	}{{first, code, id}, {observed, observedCode, observedID}} {
		if err := use(old.code, old.ticket, old.id); !errors.Is(err, errTicketLifetime) {
			t.Fatal("earlier wall time revived an expired invitation", err)
		}
	}
	if err := use(otherCode, fresh, otherID); !errors.Is(err, ErrOfferUsed) {
		t.Fatal("rollback revived a spent invitation before its nominal deadline", err)
	}
}

func TestSimultaneousOfferClaimsHaveOneWinner(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "controller")
	offer, code, id := replayInvitation(t, time.Now().Add(time.Hour))
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range cap(results) {
		wg.Go(func() {
			ctx, stop, err := code.OpenOffer(t.Context(), profile, offer, offer.Sender(), id)
			if err == nil {
				err = CheckLifetime(ctx)
				stop()
			}
			results <- err
		})
	}
	wg.Wait()
	close(results)
	var accepted int
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrOfferUsed) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("%d concurrent admissions", accepted)
	}
}

func TestInvalidReplayStateFailsClosed(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "controller")
	path := identitystate.RuntimePath(profile, "used-offers.json")
	offer, code, id := replayInvitation(t, time.Now().Add(time.Hour))
	for _, data := range []string{"", "{}", "null", "{", `{"used":{}}`, `{"expired_through_ms":0,"used":{"invalid":1}}`} {
		if err := identitystate.Replace(path, []byte(data)); err != nil {
			t.Fatal(err)
		}
		if _, stop, err := code.OpenOffer(t.Context(), profile, offer, offer.Sender(), id); err == nil {
			stop()
			t.Fatal("accepted corrupt replay state", data)
		}
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != data {
			t.Fatal("replaced unreadable replay state", err)
		}
	}
}
