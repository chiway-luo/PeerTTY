//go:build linux || darwin

package localssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fixtureReadyWriter func([]byte) (int, error)

func (f fixtureReadyWriter) Write(p []byte) (int, error) { return f(p) }

func TestLocalSSHStartupUsesLoopbackAndChecksBeforeAnnouncing(t *testing.T) {
	stageErr := errors.New("fixture startup failure")
	for _, tt := range []struct {
		name, mode, stage, diagnostic string
		want                          error
	}{
		{name: "missing executable", stage: "stat", diagnostic: "安装并初始化", want: os.ErrNotExist},
		{name: "bind permission", stage: "permission", diagnostic: "无权绑定", want: os.ErrPermission},
		{name: "bind unavailable", stage: "listen", want: stageErr},
		{name: "invalid local approver", mode: "login-open", stage: "owner", want: stageErr},
		{name: "scoped policy rejected", mode: "login-open", stage: "verify", want: stageErr},
		{name: "standard configuration rejected", stage: "check", diagnostic: "fixture diagnostic", want: stageErr},
		{name: "controller did not accept readiness message", mode: "login-open", stage: "ready", want: io.ErrClosedPipe},
		{name: "listener canceled before attach", stage: "attach", want: net.ErrClosed},
		{name: "scoped ready and selected connection", mode: "login-open"},
		{name: "standard ready and selected connection"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			var ln *net.TCPListener
			var port int
			var got []string
			dir := t.TempDir()
			ports := make(chan int, 1)
			var transcript bytes.Buffer
			writer := fixtureReadyWriter(func(b []byte) (int, error) {
				got = append(got, "ready")
				if tt.stage == "ready" {
					return 0, io.ErrClosedPipe
				}
				if tt.stage == "attach" {
					_ = ln.Close()
				}
				return transcript.Write(b)
			})
			svc := localServeServices{
				stat: func(path string) (os.FileInfo, error) {
					got = append(got, "stat")
					if path != sshd {
						t.Fatalf("wrong daemon selected: %q", path)
					}
					if tt.stage == "stat" {
						return nil, os.ErrNotExist
					}
					return nil, nil
				},
				listen: func(ctx context.Context, network, addr string) (net.Listener, error) {
					got = append(got, "listen")
					wantAddr := "127.0.0.1:22"
					if tt.mode == "login-open" {
						wantAddr = "127.0.0.1:0"
					}
					if network != "tcp4" || addr != wantAddr {
						t.Fatalf("unexpected listener=%s/%s", network, addr)
					}
					if tt.stage == "permission" {
						return nil, os.ErrPermission
					}
					if tt.stage == "listen" {
						return nil, stageErr
					}
					ln = newLocalFixtureListener(t)
					port = ln.Addr().(*net.TCPAddr).Port
					if tt.stage == "" {
						c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", ln.Addr().String())
						if err != nil {
							return nil, err
						}
						t.Cleanup(func() { _ = c.Close() })
						ports <- c.LocalAddr().(*net.TCPAddr).Port
					} else if tt.stage == "attach" {
						ports <- 5000
					}
					return ln, nil
				},
				owner: func(path string) (*user.User, *syscall.Credential, error) {
					got = append(got, "owner")
					if path != dir || tt.mode == "" {
						t.Fatal("unexpected scoped owner request")
					}
					if tt.stage == "owner" {
						return nil, nil, stageErr
					}
					return &user.User{Username: "fixture"}, nil, nil
				},
				verify: func(probe context.Context, path, name string, cred *syscall.Credential, actual int) error {
					got = append(got, "verify")
					if _, ok := probe.Deadline(); !ok || path != dir || name != "fixture" || cred != nil || actual != port {
						t.Fatalf("unexpected policy validation: %q %q %v %d", path, name, cred, actual)
					}
					if tt.stage == "verify" {
						return stageErr
					}
					return nil
				},
				check: func(cmd *exec.Cmd) ([]byte, error) {
					got = append(got, "check")
					if tt.mode != "" || !strings.Contains(strings.Join(cmd.Args, " "), " -t ") {
						t.Fatalf("unexpected preflight command: %v", cmd.Args)
					}
					if tt.stage == "check" {
						return []byte("fixture diagnostic"), stageErr
					}
					return nil, nil
				},
				run: func(_ context.Context, cmd *exec.Cmd, socket *os.File, _ io.Writer) error {
					got = append(got, "run")
					defer socket.Close()
					if !strings.Contains(strings.Join(cmd.Args, " "), " -i ") {
						t.Fatalf("wrong attach command: %v", cmd.Args)
					}
					if err := ln.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("listener remained open after handoff: %v", err)
					}
					return nil
				},
			}
			err := serveLocalWith(ctx, ports, writer, tt.mode, dir, svc)
			if !errors.Is(err, tt.want) || tt.diagnostic != "" && (err == nil || !strings.Contains(err.Error(), tt.diagnostic)) {
				t.Fatalf("startup result=%v stages=%v", err, got)
			}
			if tt.stage == "" {
				want := "READY\n"
				wantStages := "stat listen check ready run"
				if tt.mode == "login-open" {
					want = fmt.Sprintf("READY %d\n", port)
					wantStages = "stat listen owner verify ready run"
				}
				if transcript.String() != want || strings.Join(got, " ") != wantStages {
					t.Fatalf("startup announcement=%q stages=%v", transcript.String(), got)
				}
			} else if strings.Contains(strings.Join(got, " "), "run") || tt.stage != "ready" && tt.stage != "attach" && transcript.Len() != 0 {
				t.Fatalf("failed startup announced or ran a server: %q / %v", transcript.String(), got)
			}
		})
	}
}
