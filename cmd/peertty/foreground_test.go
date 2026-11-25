package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
)

// Use the actual file-exchange commands in separate processes. The target is
// an isolated loopback listener and only transmits a fixed fixture banner.
func TestFileSessionStatusAndRevocation(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocesses and direct peer connection")
	}
	for _, test := range []struct{ phase, side string }{
		{"waiting", "host"}, {"waiting", "control"}, {"ready", "host"}, {"ready", "control"},
	} {
		t.Run(test.phase+"-"+test.side, func(t *testing.T) {
			dir := t.TempDir()
			hostKey, controlKey := filepath.Join(dir, "host"), filepath.Join(dir, "control")
			offer, answer, code := filepath.Join(dir, "invite"), filepath.Join(dir, "answer"), filepath.Join(dir, "code")
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			deadline, _ := ctx.Deadline()
			listener.SetDeadline(deadline)

			start := func(args ...string) (io.WriteCloser, io.Reader, *bufio.Scanner) {
				t.Helper()
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(ctx, exe, args...)
				cmd.Env = append(os.Environ(), "PEERTTY_TEST_PROXY=1")
				in, err := cmd.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				out, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				log, err := cmd.StderrPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { in.Close(); cmd.Wait() })
				return in, out, bufio.NewScanner(log)
			}
			port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
			hostIn, _, log := start("host", "-key", hostKey, "-offer", offer, "-ttl", "1m", "-stun", "none", "-ssh-port", port)
			const prefix = "Pairing code (deliver separately): "
			for log.Scan() && !strings.HasPrefix(log.Text(), prefix) {
			}
			pair, ok := strings.CutPrefix(log.Text(), prefix)
			if !ok {
				t.Fatal("host did not publish an invitation")
			}
			if !log.Scan() || !strings.Contains(log.Text(), "Your SSH server decides which accounts may log in") {
				t.Fatal("file approval omitted the scope of system SSH access")
			}
			if err = os.WriteFile(code, []byte(pair), 0600); err != nil {
				t.Fatal(err)
			}
			check := func(key, role, phase string, terminals int) active.State {
				t.Helper()
				st, err := active.Status(ctx, key)
				if err != nil || !st.OneShot || st.Role != role || st.Phase != phase || st.Terminals != terminals || st.TimeLeft() <= 0 {
					t.Fatalf("status role=%s phase=%s terminals=%d: %v", st.Role, st.Phase, st.Terminals, err)
				}
				return st
			}
			check(hostKey, "host", "waiting", 0)
			key := hostKey
			if test.side == "control" {
				key = controlKey
			}
			var target *net.TCPConn
			if test.side == "control" || test.phase == "ready" {
				_, output, log := start("connect", "-key", controlKey, "-offer", offer, "-answer", answer, "-code-file", code, "-stun", "none")
				if !log.Scan() || !strings.Contains(log.Text(), "for approval") {
					t.Fatal("controller did not publish a receipt")
				}
				check(controlKey, "control", "waiting", 0)
				if test.phase == "ready" {
					if _, err = io.WriteString(hostIn, answer+"\n"); err != nil {
						t.Fatal(err)
					}
					target, err = listener.AcceptTCP()
					if err != nil {
						t.Fatal(err)
					}
					defer target.Close()
					target.SetDeadline(deadline)
					const banner = "SSH-2.0-PeerTTYFixture\r\n"
					if _, err = io.WriteString(target, banner); err != nil {
						t.Fatal(err)
					}
					b := make([]byte, len(banner))
					if _, err = io.ReadFull(output, b); err != nil || string(b) != banner {
						t.Fatal("established session did not carry the fixture banner", err)
					}
					host := check(hostKey, "host", "ready", 1)
					control := check(controlKey, "control", "ready", 1)
					if host.Route == "" || control.Route == "" {
						t.Fatal("missing direct route")
					}
					if conn, err := active.Pipe(ctx, controlKey, control.ID); err == nil {
						conn.Close()
						t.Fatal("single-use session admitted another stream")
					}
					for _, args := range [][]string{
						{"link", "-key", controlKey}, {"sftp", "-key", controlKey}, {"cp", "-key", controlKey, ":/example", filepath.Join(dir, "copy")},
					} {
						if _, err := commandOutput(t, args...); !errors.Is(err, active.ErrOneShot) {
							t.Fatalf("%s did not report the single-use limit: %v", args[0], err)
						}
					}
				}
			}
			if out, err := commandOutput(t, "status", "-key", key); err != nil || !strings.Contains(out, "单次前台会话") {
				t.Fatalf("status failed to identify the foreground session: %v", err)
			}
			if out, err := commandOutput(t, "revoke", "-key", key); err != nil || !strings.Contains(out, "已撤销") {
				t.Fatalf("revoke did not confirm completion: %v", err)
			}
			if _, err := active.Status(ctx, key); !errors.Is(err, active.ErrInactive) {
				t.Fatalf("revoked session still visible: %v", err)
			}
			lease, err := grant.LeaseIdentity(key)
			if err != nil {
				t.Fatal("revoked session retained its lease", err)
			}
			lease.Close()
			if target != nil {
				if _, err := target.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("revocation did not close the existing stream: %v", err)
				}
			}
		})
	}
}
