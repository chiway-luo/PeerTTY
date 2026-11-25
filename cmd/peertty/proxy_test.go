package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/localssh"
	"peertty/internal/session"
	"peertty/internal/transport"
)

// OpenSSH starts this test binary as its real ProxyCommand subprocess.
func TestMain(m *testing.M) {
	if os.Getenv("PEERTTY_TEST_PROXY") == "1" && len(os.Args) > 1 {
		switch os.Args[1] {
		case "menu", "host", "connect", "link", "_link-proxy", active.Command:
			main()
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// Win32 OpenSSH 9.5 may leave a native stdout pipe open even when a
// direct (non-proxied) SSH command has finished. Use real files on Windows
// so these integration tests exercise the protocol and exit statuses.
func captureSSHTestOutput(t *testing.T, cmd *exec.Cmd) (stdout, stderr []byte, err error) {
	t.Helper()
	if runtime.GOOS != "windows" {
		var diag bytes.Buffer
		cmd.Stderr = &diag
		out, e := cmd.Output()
		return out, diag.Bytes(), e
	}
	dir := t.TempDir()
	out, e := os.Create(filepath.Join(dir, "stdout"))
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	diag, e := os.Create(filepath.Join(dir, "stderr"))
	if e != nil {
		t.Fatal(e)
	}
	defer diag.Close()
	cmd.Stdout, cmd.Stderr = out, diag
	err = cmd.Run()
	stdout, e = os.ReadFile(out.Name())
	if e != nil {
		t.Fatal(e)
	}
	stderr, e = os.ReadFile(diag.Name())
	if e != nil {
		t.Fatal(e)
	}
	return stdout, stderr, err
}

func TestNativeSSHProxyExit(t *testing.T) {
	if testing.Short() {
		t.Skip("needs native SSH and a peer connection")
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("native OpenSSH client unavailable")
	}
	dir := t.TempDir()
	loginKey, err := localssh.NewLoginKey(filepath.Join(dir, "login.key"))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, content []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("ssh.conf", nil)
	authorized, err := ssh.NewPublicKey(loginKey)
	if err != nil {
		t.Fatal(err)
	}
	_, sshHostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(sshHostKey)
	if err != nil {
		t.Fatal(err)
	}
	write("known_hosts", append([]byte("peertty-fixture "), ssh.MarshalAuthorizedKey(signer.PublicKey())...))
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), authorized.Marshal()) {
			return nil, errors.New("unknown test identity")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := make(chan error, 1)
	go func() { server <- serveMarker(listener, cfg) }()

	id := func(name string) (string, ed25519.PrivateKey) {
		t.Helper()
		path := filepath.Join(dir, name)
		fp, err := grant.NewIdentity(path)
		if err != nil {
			t.Fatal(err)
		}
		key, err := grant.LoadIdentity(path)
		if err != nil {
			t.Fatal(err)
		}
		return fp, key
	}
	hostID, key := id("host.key")
	operatorID, _ := id("engineer.key")
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	offered, finished := make(chan struct{}), make(chan error, 1)
	answer := filepath.Join(dir, "test.answer")
	go func() {
		finished <- session.Host(ctx, session.HostOptions{
			Options: session.Options{Key: key, Peer: operatorID, OfferPath: filepath.Join(dir, "test.offer"), Status: io.Discard},
			TTL:     time.Minute, SSHPort: listener.Addr().(*net.TCPAddr).Port,
			Approval: func(ctx context.Context, code grant.PairingCode) (string, error) {
				if err := os.WriteFile(filepath.Join(dir, "test.code"), []byte(code), 0600); err != nil {
					return "", err
				}
				close(offered)
				tick := time.NewTicker(10 * time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-ctx.Done():
						return "", ctx.Err()
					case <-tick.C:
						if _, err := grant.Read(answer); err == nil {
							return answer, nil
						}
					}
				}
			},
		})
	}()
	select {
	case <-offered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	proxy := fmt.Sprintf(`ProxyCommand="%s" connect -stun none -key engineer.key -peer %s -offer test.offer -answer test.answer -code-file test.code`, bin, hostID)
	cmd := exec.CommandContext(ctx, sshPath, "-F", "ssh.conf", "-o", "ControlPath=none", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=known_hosts",
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", proxy, "-i", "login.key", "-tt", "fixture@peertty-fixture", "marker")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PEERTTY_TEST_PROXY=1")
	cmd.WaitDelay = 3 * time.Second
	output, diag, err := captureSSHTestOutput(t, cmd)
	out := append(output, diag...)
	if err != nil || !bytes.Contains(out, []byte("PEERTTY_PTY_OK")) {
		t.Fatalf("native SSH: %v\n%s", err, out)
	}
	select {
	case err := <-server:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-finished:
		// The native Win32 client can terminate its ProxyCommand after a
		// successful SSH exit, before PeerTTY's bridge exchanges a final ACK.
		// The SSH result and fixture shutdown above must still both succeed.
		if err != nil && !(runtime.GOOS == "windows" && errors.Is(err, transport.ErrDirectDisconnected)) {
			t.Fatalf("host after SSH exit: %v\n%s", err, out)
		}
	case <-ctx.Done():
		t.Fatal("host outlived SSH", ctx.Err())
	}
}

// The fixture answers one fixed PTY request. It never starts a shell.
func serveMarker(l net.Listener, cfg *ssh.ServerConfig) error {
	raw, err := l.Accept()
	if err != nil {
		return err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	conn, channels, global, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	go ssh.DiscardRequests(global)
	request, ok := <-channels
	if !ok || request.ChannelType() != "session" {
		return errors.New("expected SSH session")
	}
	ch, requests, err := request.Accept()
	if err != nil {
		return err
	}
	var pty bool
	for r := range requests {
		switch r.Type {
		case "pty-req":
			pty = true
			_ = r.Reply(true, nil)
		case "exec":
			var payload struct{ Command string }
			if ssh.Unmarshal(r.Payload, &payload) != nil || !((payload.Command == "marker" && pty) || (payload.Command == "marker-exit" && !pty)) {
				return errors.New("unexpected SSH request")
			}
			if err := r.Reply(true, nil); err != nil {
				return err
			}
			if _, err := io.WriteString(ch, "PEERTTY_PTY_OK\r\n"); err != nil {
				return err
			}
			var status uint32
			if payload.Command == "marker-exit" {
				status = 7
			}
			if _, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status})); err != nil {
				return err
			}
			if err := ch.Close(); err != nil {
				return err
			}
			conn.Wait()
			return nil
		default:
			_ = r.Reply(false, nil)
		}
	}
	return errors.New("SSH session ended before marker")
}

// Exercise the installed entry points, native command mode and SSH exit status
// using a fixed local SSH response and two independently owned grant workers.
func TestLinkCommandStdoutAndExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("needs native SSH and a peer connection")
	}
	if _, err := localssh.ClientPath(); err != nil {
		t.Skip(err)
	}
	t.Setenv("PEERTTY_TEST_PROXY", "1")
	dir := t.TempDir()
	host := filepath.Join(dir, "host.key")
	client := filepath.Join(dir, "client.key")
	_, err := grant.NewIdentity(host)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grant.NewIdentity(client); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "login.key")
	pub, err := localssh.NewLoginKey(identity)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(k.Marshal(), key.Marshal()) {
			return nil, errors.New("unknown key")
		}
		return nil, nil
	}}
	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hostPriv)
	cfg.AddHostKey(signer)
	known := filepath.Join(dir, "known_hosts")
	conf := filepath.Join(dir, "ssh.conf")
	if err = os.WriteFile(conf, []byte("Host *\n BatchMode yes\n StrictHostKeyChecking yes\n UserKnownHostsFile \""+filepath.ToSlash(known)+"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
	defer stop()
	wait := func(path, phase string) active.State {
		t.Helper()
		for ctx.Err() == nil {
			s, err := active.Status(ctx, path)
			if err == nil {
				if s.Phase == phase {
					return s
				}
				if s.Phase == "offline" {
					t.Fatal(s.Note)
				}
			}
			time.Sleep(15 * time.Millisecond)
		}
		t.Fatal("waiting for", phase)
		return active.State{}
	}
	start := func(o active.Options) {
		t.Helper()
		s, err := active.Start(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = active.Revoke(context.Background(), o.Key, s.ID) })
	}
	start(active.Options{Role: "host", Key: host, Port: l.Addr().(*net.TCPAddr).Port, TTL: time.Minute})
	h := wait(host, "waiting")
	offer, err := grant.Read(h.Exchange)
	if err != nil {
		t.Fatal(err)
	}
	alias := "peertty-" + strings.TrimPrefix(grant.Fingerprint(offer.Claims.Issuer), "sha256:")
	if err = localssh.PinLoginHost(known, alias, hostPub); err != nil {
		t.Fatal(err)
	}
	start(active.Options{Role: "control", Key: client, Offer: offer, PairingCode: h.PairingCode, User: "fixture", Identity: identity, SSHConfig: conf})
	c := wait(client, "waiting")
	answer, err := grant.Read(c.Exchange)
	if err != nil {
		t.Fatal(err)
	}
	if err = active.Approve(ctx, host, h.ID, answer); err != nil {
		t.Fatal(err)
	}
	wait(client, "ready")
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"script", []string{"--", "marker-exit"}, 7},
		{"terminal", []string{"-t", "--", "marker"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := make(chan error, 1)
			go func() { fixture <- serveMarker(l, cfg) }()
			args := append([]string{"link", "-key", client}, tc.args...)
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.WaitDelay = 3 * time.Second // Bound inherited output pipes on cancellation.
			output, diag, err := captureSSHTestOutput(t, cmd)
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != tc.code || strings.TrimSpace(string(output)) != "PEERTTY_PTY_OK" {
				t.Fatalf("exit=%v stdout=%q stderr=%q", err, output, diag)
			}
			select {
			case err := <-fixture:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
