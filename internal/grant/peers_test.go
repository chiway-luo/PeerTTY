package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
)

func TestShortFingerprintAndKnownPeersTOFU(t *testing.T) {
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fpA, fpB := Fingerprint(pubA), Fingerprint(pubB)
	shortA := ShortFingerprint(fpA)
	if len(shortA) != 19 || shortA[4] != '-' || shortA[9] != '-' || shortA[14] != '-' {
		t.Fatalf("unexpected short fingerprint %q", shortA)
	}
	if ShortFingerprint("invalid") != "" {
		t.Fatal("accepted invalid fingerprint")
	}

	keyPath := filepath.Join(t.TempDir(), "device.key")
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	if check := LookupPeer(keyPath, fpA, "lab-host"); check.Trust != PeerNew {
		t.Fatalf("initial trust = %v, want PeerNew", check.Trust)
	}
	if err := RecordPeer(keyPath, fpA, "lab-host", now); err != nil {
		t.Fatal(err)
	}
	check := LookupPeer(keyPath, fpA, "lab-host")
	if check.Trust != PeerKnown || check.PreviousName != "lab-host" || !check.LastSeen.Equal(now) {
		t.Fatalf("known peer check = %+v", check)
	}
	// A different public key claiming the same device name triggers a mismatch warning.
	conflict := LookupPeer(keyPath, fpB, "LAB-HOST")
	if conflict.Trust != PeerKeyMismatch || conflict.ConflictID != shortA {
		t.Fatalf("conflict check = %+v, want PeerKeyMismatch with %s", conflict, shortA)
	}
	// A different key with a distinct name is simply new.
	if check := LookupPeer(keyPath, fpB, "other-host"); check.Trust != PeerNew {
		t.Fatalf("distinct host check = %+v, want PeerNew", check)
	}
}
