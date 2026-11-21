package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/grant"
)

func TestHostValidatesGrantBeforeExchange(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ttl        time.Duration
		port       int
		pair       bool
		peer, want string
	}{
		{"zero TTL", 0, 22, true, "", "TTL"},
		{"overlong TTL", grant.MaxTTL + time.Second, 22, true, "", "TTL"},
		{"invalid port", time.Minute, 65536, true, "", "port"},
		{"conflicting roles", time.Minute, 22, true, "pinned", "pinned"},
		{"missing controller", time.Minute, 22, false, "", "fingerprint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Peer: tc.peer, PairOnApproval: tc.pair, STUN: "none"}
			err := RunHost(t.Context(), cfg, tc.ttl, tc.port, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFileExchangePreservesOfferOnRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	host, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var status bytes.Buffer
	opts := Options{Key: key, Peer: grant.Fingerprint(control), STUN: "none", OfferPath: filepath.Join(dir, "request.offer"), Status: &status}
	if err := Connect(ctx, opts, filepath.Join(dir, "reply"), nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing invitation: %v", err)
	}
	declined := errors.New("operator declined")
	settings := HostOptions{Options: opts, SSHPort: 22, TTL: time.Minute, Approval: func(context.Context) (string, error) {
		return "", declined
	}}
	if err := Host(ctx, settings); !errors.Is(err, declined) || !strings.Contains(status.String(), opts.OfferPath) {
		t.Fatalf("declined invitation: %v, status %q", err, status.String())
	}
	original, err := os.ReadFile(opts.OfferPath)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := grant.Parse(original)
	if err != nil || ticket.VerifyOffer(grant.Fingerprint(host), opts.Peer, time.Now()) != nil {
		t.Fatal("file exchange published an invalid offer", err)
	}
	if err := Host(ctx, settings); !errors.Is(err, os.ErrExist) {
		t.Fatalf("reused path: %v", err)
	}
	after, err := os.ReadFile(opts.OfferPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("retry replaced the published invitation", err)
	}
}
