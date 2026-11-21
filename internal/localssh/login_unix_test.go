//go:build darwin || linux

package localssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == GuardCommand {
		if err := Serve(context.Background(), os.Args[2:], os.Stdin, os.Stdout); err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Run explicitly inside the disposable Linux lab, as a normal local account
// with a pre-existing loopback SSH listener. No account key file is changed.
func TestApprovedLoginBesideExistingSSHD(t *testing.T) {
	if os.Getenv("PEERTTY_LAB_OPEN_SSH") != "1" {
		t.Skip("requires the lab's existing loopback sshd")
	}
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
	defer stop()
	existing, err := dial(ctx, "127.0.0.1:22")
	if err != nil {
		t.Fatal(err)
	}
	existing.Close()
	s, err := PrepareLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Authorize(pub); err != nil {
		t.Fatal(err)
	}
	c, err := s.OpenAuthorized(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	defer c.Close()
	if c.RemoteAddr().String() == "127.0.0.1:22" {
		t.Fatal("expected the single-connection sshd on its own port")
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	hostKey, _ := ssh.NewPublicKey(s.HostKey)
	wire, channels, requests, err := ssh.NewClientConn(c, "session", &ssh.ClientConfig{User: s.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey)})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(wire, channels, requests)
	defer client.Close()
	term, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := term.Output("id -un")
	if err != nil || strings.TrimSpace(string(out)) != s.User {
		t.Fatalf("current-account login: %q %v", out, err)
	}
}
