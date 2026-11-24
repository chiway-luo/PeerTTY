package localssh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAttachConfirmsLocalPortAndReplaysIdentification(t *testing.T) {
	const preamble = "fixture notice\r\n"
	const identification = "SSH-2.0-PeerTTYFixture\r\n"
	for _, tc := range []struct {
		name, status, serverText, wantErr string
		ephemeral                         bool
	}{
		{"ephemeral port", "ATTACHED", preamble + identification + "buffered-data", "", true},
		{"fixed endpoint", "ATTACHED", identification, "", false},
		{"helper rejects attachment", "fixture failed ownership", "", "fixture failed ownership", true},
		{"non-SSH service fails handshake", "ATTACHED", "fixture notice but no identification\r\n", "未能完成启动握手", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			deadline, _ := ctx.Deadline()
			if err := ln.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			type serverResult struct {
				port int
				err  error
			}
			server := make(chan serverResult, 1)
			go func() {
				s, acceptErr := ln.AcceptTCP()
				if acceptErr != nil {
					server <- serverResult{err: acceptErr}
					return
				}
				defer s.Close()
				_ = s.SetWriteDeadline(deadline)
				_, writeErr := io.WriteString(s, tc.serverText)
				server <- serverResult{port: s.RemoteAddr().(*net.TCPAddr).Port, err: writeErr}
			}()

			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestAttachLoopbackHelper$")
			addr, ready := ln.Addr().String(), "READY"
			if tc.ephemeral {
				addr = "127.0.0.1:0"
				ready += " " + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
			}
			report := filepath.Join(t.TempDir(), "client-port")
			cmd.Env = append(os.Environ(), "PEERTTY_TEST_ATTACH_READY="+ready, "PEERTTY_TEST_ATTACH_STATUS="+tc.status, "PEERTTY_TEST_ATTACH_REPORT="+report)
			c, err := attach(ctx, addr, cmd)
			if c != nil {
				defer c.Release()
				defer c.Close()
			}
			if tc.wantErr != "" {
				if c != nil || err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected %q, got connection %v / %v", tc.wantErr, c != nil, err)
				}
			} else {
				if err != nil || c == nil || !c.Temporary() {
					t.Fatalf("validated guard connection not returned: %v", err)
				}
				_ = c.SetReadDeadline(deadline)
				payload, err := io.ReadAll(c)
				if err != nil || string(payload) != tc.serverText {
					t.Fatalf("identification or buffered bytes lost: %q / %v", payload, err)
				}
				if tc.ephemeral {
					cancel()
					select {
					case <-c.guard.done:
					case <-time.After(5 * time.Second):
						t.Fatal("helper survived grant cancellation while the connection was retained")
					}
				}
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
				if err := c.Release(); err != nil {
					t.Fatal(err)
				}
			}
			if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
				t.Fatal("helper was not cleanly reaped")
			}
			observed := <-server
			contents, readErr := os.ReadFile(report)
			if observed.err != nil || readErr != nil || string(contents) != strconv.Itoa(observed.port)+"\n" {
				t.Fatalf("helper did not receive connected client's loopback port: %q vs %d (%v, %v)", contents, observed.port, readErr, observed.err)
			}
		})
	}
}

func TestAttachLoopbackHelper(t *testing.T) {
	ready := os.Getenv("PEERTTY_TEST_ATTACH_READY")
	if ready == "" {
		return
	}
	fmt.Fprintln(os.Stdout, ready)
	in := bufio.NewReader(os.Stdin)
	line, err := in.ReadString('\n')
	if err != nil || os.WriteFile(os.Getenv("PEERTTY_TEST_ATTACH_REPORT"), []byte(line), 0600) != nil {
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, os.Getenv("PEERTTY_TEST_ATTACH_STATUS"))
	_, _ = io.Copy(io.Discard, in)
	os.Exit(0)
}
