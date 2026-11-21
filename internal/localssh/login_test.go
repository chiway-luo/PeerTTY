package localssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"peertty/internal/grant"
)

func TestLoginFilesBindOneHostAndController(t *testing.T) {
	dir := t.TempDir()
	slot := filepath.Join(dir, "session")
	if err := os.Mkdir(slot, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(slot, "host.key")
	public, err := NewLoginKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewLoginKey(keyPath); !errors.Is(err, os.ErrExist) {
		t.Fatalf("key overwritten: %v", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	if err := PinLoginHost(known, "device-test", public); err != nil {
		t.Fatal(err)
	}
	line, err := os.ReadFile(known)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(line, append([]byte("device-test "), ssh.MarshalAuthorizedKey(signer.PublicKey())...)) {
		t.Fatal("pinned host differs from generated private key")
	}
	login := &Login{User: "fixture", dir: slot}
	if err = login.Authorize(ed25519.PublicKey{1}); err == nil {
		t.Fatal("short public key accepted")
	}
	controller, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = login.Authorize(controller); err != nil {
		t.Fatal(err)
	}
	if err = login.Authorize(public); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second key replaced approved one: %v", err)
	}
	controllerKey, err := ssh.NewPublicKey(controller)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(slot, "authorized-fixture"))
	if err != nil || !bytes.Equal(data, append([]byte("restrict,pty "), ssh.MarshalAuthorizedKey(controllerKey)...)) {
		t.Fatal("wrong restrictions or controller key", err)
	}
	if _, err := login.OpenAuthorized(context.Background()); err == nil {
		t.Fatal("started a login without a deadline")
	}
	if err = login.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(slot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("session survived close", err)
	}
	if _, err = os.Stat(known); err != nil {
		t.Fatal("sibling file removed", err)
	}
}

func TestGuardValidatesDeadlineBeforeReadiness(t *testing.T) {
	now := time.Now()
	future := strconv.FormatInt(now.Add(grant.MaxTTL+time.Hour).UnixMilli(), 10)
	expired := strconv.FormatInt(now.Add(-time.Second).UnixMilli(), 10)
	for _, args := range [][]string{nil, {"malformed"}, {expired}, {future, "login-open", t.TempDir()}, {future, "unknown-mode", t.TempDir()}} {
		var status bytes.Buffer
		err := Serve(t.Context(), args, strings.NewReader(""), &status)
		if err == nil || status.Len() != 0 {
			t.Fatalf("invalid guard arguments announced readiness: %q", status.String())
		}
	}
}

func TestGuardWaitsForSelectedPortOrCancellation(t *testing.T) {
	var out bytes.Buffer
	ports := make(chan int, 1)
	ports <- 4242
	if port, err := peerPort(t.Context(), ports, &out, "READY"); err != nil || port != 4242 || out.String() != "READY\n" {
		t.Fatalf("handshake: port %d, output %q, error %v", port, out.String(), err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := peerPort(ctx, ports, io.Discard, "READY"); !errors.Is(err, context.Canceled) {
		t.Fatalf("abandoned handshake: %v", err)
	}
}

func TestEffectiveLoginPolicy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "session with spaces")
	wantFile := filepath.ToSlash(filepath.Join(dir, "authorized-%u"))
	config := "pubkeyauthentication yes\nauthorizedkeysfile \"" + wantFile + "\"\ntrustedusercakeys none\ndisableforwarding yes\npasswordauthentication no\nmaxsessions 1\nauthenticationmethods publickey\n"
	if runtime.GOOS != "windows" {
		config += "authorizedkeyscommand none\nhostbasedauthentication no\nkbdinteractiveauthentication no\npermitrootlogin no\n"
	}
	if err := checkLoginPolicy([]byte(config), dir); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"missing setting", "maxsessions 1\n", ""},
		{"additional authentication", "authenticationmethods publickey", "authenticationmethods publickey,password"},
		{"account keys", wantFile, ".ssh/authorized_keys"},
		{"forwarding", "disableforwarding yes", "disableforwarding no"},
		{"extra password method", "passwordauthentication no", "passwordauthentication no\npermitemptypasswords yes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkLoginPolicy([]byte(strings.Replace(config, tc.old, tc.new, 1)), dir); err == nil {
				t.Fatal("accepted incompatible policy")
			}
		})
	}
}

func TestSessionSSHArgumentsUseAccountScopedKeyFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "session with spaces")
	args := loginArgs(dir)
	if len(args) < 2 || args[0] != "-h" || args[1] != filepath.Join(dir, "host.key") {
		t.Fatal("session host key missing", args)
	}
	keyFile := "AuthorizedKeysFile=" + strconv.Quote(filepath.ToSlash(filepath.Join(dir, "authorized-%u")))
	for _, setting := range []string{keyFile, "TrustedUserCAKeys=none", "PasswordAuthentication=no", "DisableForwarding=yes", "MaxSessions=1"} {
		if !slices.Contains(args, setting) {
			t.Errorf("missing session setting %q", setting)
		}
	}
}

func TestDiagnosticTailKeepsMostRecentBytes(t *testing.T) {
	var tail diagnosticTail
	var all []byte
	for _, size := range []int{1500, 800, 1, 4200, 12} {
		chunk := bytes.Repeat([]byte{byte(size % 251)}, size)
		all = append(all, chunk...)
		if n, err := tail.Write(chunk); n != len(chunk) || err != nil {
			t.Fatalf("write: %d %v", n, err)
		}
		if !bytes.Equal(tail, all[max(0, len(all)-2048):]) {
			t.Fatal("incorrect diagnostic suffix")
		}
	}
}
