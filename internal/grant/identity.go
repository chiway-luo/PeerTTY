// Package grant signs and verifies the files exchanged for a single session.
package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Fingerprint(key ed25519.PublicKey) string {
	hash := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(hash[:])
}

// ShortFingerprint formats the first 64 bits of a device fingerprint in four
// hyphenated groups for quick out-of-band confirmation alongside a device name.
func ShortFingerprint(fp string) string {
	raw, ok := strings.CutPrefix(fp, "sha256:")
	if !ok || len(raw) < 16 {
		return ""
	}
	return raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:16]
}

func ValidFingerprint(value string) bool {
	raw, ok := strings.CutPrefix(value, "sha256:")
	if !ok || len(raw) != 2*sha256.Size || raw != strings.ToLower(raw) {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func NewIdentity(path string) (string, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	// Publish a complete key without replacing another first-run process's key.
	f, err := os.CreateTemp(filepath.Dir(path), ".peertty-key-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return "", err
	}
	if err = os.Link(f.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", err
		}
		// Removable volumes may not support hard links; keep the no-clobber contract.
		if err = writeNew(path, data); err != nil {
			return "", err
		}
	}
	return Fingerprint(pub), nil
}

func LoadIdentity(path string) (ed25519.PrivateKey, error) {
	data, err := readLimited(path, 4096)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("expected a PKCS#8 Ed25519 private key")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("expected an Ed25519 private key")
	}
	return key, nil
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(data)) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return data, err
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}
