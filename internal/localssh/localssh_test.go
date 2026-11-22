package localssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestExistingAndClosedCustomSSHPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := Open(t.Context(), port)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	if conn.Temporary() {
		t.Fatal("existing service was claimed")
	}
	conn.Close()
	if err := conn.Release(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal("existing listener was closed", err)
	}
	if _, err := Open(t.Context(), port); !errors.Is(err, refused) {
		t.Fatal("closed custom port must not activate a new service", err)
	}
}

// A subprocess exercises real control-pipe EOF without privileged ports or sshd.
func TestGuardFixture(t *testing.T) {
	if os.Getenv("PEERTTY_TEST_LOCAL_SSH_GUARD") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, "READY")
	input := bufio.NewReader(os.Stdin)
	if _, err := input.ReadString('\n'); err != nil {
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, "ATTACHED")
	_, _ = io.Copy(io.Discard, input)
	os.Exit(0)
}

func TestTemporarySSHIdentifiesBeforeHandoff(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a guard subprocess and checks the TCP handoff")
	}
	for _, banner := range []string{"SSH-2.0-OpenSSH_Test\r\n", "Welcome notice\r\nSSH-2.0-OpenSSH_Test\r\n", "not-ssh\n"} {
		t.Run(strings.TrimSpace(banner), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			echoDone := make(chan error, 1)
			go func() {
				peer, err := listener.Accept()
				if err == nil {
					defer peer.Close()
					if _, err = io.WriteString(peer, banner); err == nil {
						_, err = io.Copy(io.Discard, peer)
					}
				}
				echoDone <- err
			}()
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(exe, "-test.run=^TestGuardFixture$")
			child.Env = append(os.Environ(), "PEERTTY_TEST_LOCAL_SSH_GUARD=1")
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			conn, err := attach(ctx, listener.Addr().String(), child)
			if !strings.Contains(banner, "SSH-2.0-") {
				if err == nil {
					conn.Close()
					conn.Release()
					t.Fatal("accepted a non-SSH server")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				data := make([]byte, len(banner))
				_, readErr := io.ReadFull(conn, data)
				conn.Close()
				if err := conn.Release(); err != nil {
					t.Fatal(err)
				}
				if !conn.Temporary() || readErr != nil || string(data) != banner {
					t.Fatalf("SSH identification changed: %q, %v", data, readErr)
				}
			}
			if err := <-echoDone; err != nil {
				t.Fatal(err)
			}
			if child.ProcessState == nil || !child.ProcessState.Success() {
				t.Fatal("guard did not exit on control-pipe EOF")
			}
		})
	}
}

func TestManagedKeyNeedsNativeUserKeyPolicy(t *testing.T) {
	base := "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nauthenticationmethods any\nmaxsessions 10\n"
	if err := checkUserKeyPolicy([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{{" .ssh/authorized_keys", " /etc/central_keys/%u"}, {" any", " publickey,keyboard-interactive"}, {" yes", " no"}, {" 10", " 0"}} {
		if checkUserKeyPolicy([]byte(strings.Replace(base, change[0], change[1], 1))) == nil {
			t.Fatal("accepted restricted policy", change)
		}
	}
}

func TestReadSSHBannerReplayAndToolPath(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		ok         bool
	}{
		{"standard", "SSH-2.0-OpenSSH_9.6\r\npayload", true},
		{"compat", "SSH-1.99-Legacy\r\n", true},
		{"rfc4253 preamble", "Notice: authorized only\r\nSecond line\r\nSSH-2.0-OpenSSH_9.6\r\nrest", true},
		{"ssh1 rejected", "SSH-1.5-Old\r\n", false},
		{"oversized", strings.Repeat("A", 9000) + "\nSSH-2.0-OpenSSH\r\n", false},
		{"eof without banner", "hello\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				c, err := ln.Accept()
				if err == nil {
					_, _ = io.WriteString(c, tc.wire)
					_ = c.Close()
				}
			}()
			c, err := dial(t.Context(), ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			r, err := readSSHBannerReplay(c, time.Now().Add(2*time.Second))
			if (err == nil) != tc.ok {
				t.Fatalf("readSSHBannerReplay(%q) err=%v, want ok=%v", tc.name, err, tc.ok)
			}
			if tc.ok {
				got, err := io.ReadAll(r)
				if err != nil || string(got) != tc.wire {
					t.Fatalf("replayed %q, want %q (err=%v)", got, tc.wire, err)
				}
			}
		})
	}
	if _, err := ToolPath("definitely-nonexistent-peertty-tool-xyz"); err == nil {
		t.Fatal("ToolPath succeeded for nonexistent binary")
	}
	if got := cmdError(exec.Command("/bin/false"), errors.New("boom"), " detail \n"); !strings.Contains(got.Error(), "detail") {
		t.Fatalf("cmdError = %v", got)
	}
}
