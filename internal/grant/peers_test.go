package grant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
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
	if err := RecordPeer(keyPath, fpB, "other-host", now); err != nil {
		t.Fatal(err)
	}
	if got := LookupPeer(keyPath, fpB, "LAB-HOST"); got.Trust != PeerKeyMismatch || got.ConflictID != shortA {
		t.Fatalf("renamed known peer masked a name conflict: %+v", got)
	}
	if got := LookupPeer(keyPath, fpB, "new-name"); got.Trust != PeerKnown || got.PreviousName != "other-host" {
		t.Fatalf("ordinary rename lost the known identity: %+v", got)
	}
}

func TestTrustHistoryIsPreservedWhenLargeOrUnreadable(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	fp := Fingerprint([]byte("first"))
	if err := RecordPeer(key, fp, "first", time.Now()); err != nil {
		t.Fatal(err)
	}
	path := peersPath(key)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A legitimate 0.4.0 history could exceed its former 256 KiB read limit.
	raw = append(bytes.Repeat([]byte(" "), 256*1024), raw...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RecordPeer(key, Fingerprint([]byte("second")), "second", time.Now()); err != nil {
		t.Fatal(err)
	}
	if LookupPeer(key, fp, "first").Trust != PeerKnown {
		t.Fatal("lost previous device")
	}
	for _, damaged := range []string{"{damaged", "null", `{"foreign":{}}`, fmt.Sprintf(`{"%s":{}}`, fp)} {
		if err := os.WriteFile(path, []byte(damaged), 0600); err != nil {
			t.Fatal(err)
		}
		if err := RecordPeer(key, fp, "first", time.Now()); err == nil {
			t.Fatal("overwrote unreadable history")
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != damaged || LookupPeer(key, fp, "first").Trust != PeerHistoryUnavailable {
			t.Fatal("lost damaged history", err)
		}
	}
}

func TestConcurrentRecordsKeepEveryDevice(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	done := make(chan error, 8)
	for i := range 8 {
		go func() { name := fmt.Sprint(i); done <- RecordPeer(key, Fingerprint([]byte(name)), name, time.Now()) }()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for i := range 8 {
		name := fmt.Sprint(i)
		if LookupPeer(key, Fingerprint([]byte(name)), name).Trust != PeerKnown {
			t.Fatal("lost device", name)
		}
	}
}
