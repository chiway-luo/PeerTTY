package grant

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityRejectsOtherKeyTypesAndInvalidFingerprints(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "other.key")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadIdentity(p); got != nil || err == nil || !strings.Contains(err.Error(), "expected an Ed25519") {
		t.Fatalf("mistyped identity was not rejected: %v", err)
	}
	for _, fp := range []string{"sha256:123", "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64), "missing"} {
		if ValidFingerprint(fp) {
			t.Fatalf("accepted invalid fingerprint %q", fp)
		}
	}
	if ShortFingerprint("sha256:123") != "" {
		t.Fatal("short fingerprint unexpectedly rendered")
	}
}

func TestIdentityPublicationDoesNotCreateParentsOrOverwrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "absent", "device.key")
	if fp, err := NewIdentity(p); fp != "" || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new identity without directory: %q, %v", fp, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("key generation left temp files: %v / %v", entries, err)
	}
	p = filepath.Join(dir, "fallback.key")
	if err := writeNew(p, []byte("original key fixture")); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(p, []byte("replacement")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("fallback creation overwrote existing file: %v", err)
	}
	if got, err := os.ReadFile(p); err != nil || string(got) != "original key fixture" {
		t.Fatalf("unexpected file contents %q / %v", got, err)
	}
}
