package localssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAttachmentStartupFailuresDoNotLeaveAHelper(t *testing.T) {
	tests := []struct {
		mode, addr, want string
	}{
		{"missing", "127.0.0.1:0", "启动本机 OpenSSH"},
		{"bad ephemeral port", "127.0.0.1:0", "没有返回有效回环端口"},
		{"missing readiness prefix", "127.0.0.1:0", "没有返回有效回环端口"},
		{"zero ephemeral port", "127.0.0.1:0", "没有返回有效回环端口"},
		{"ephemeral guard exits cleanly", "127.0.0.1:0", "本机 SSH 启动进程已退出"},
		{"guard exits", "127.0.0.1:1", "fixture startup error"},
		{"guard reports error", "127.0.0.1:1", "fixture no service"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var cmd *exec.Cmd
			if tt.mode == "missing" {
				cmd = exec.Command(filepath.Join(t.TempDir(), "missing-guard"))
			} else {
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				cmd = exec.Command(exe, "-test.run=^TestAttachmentFailureHelper$")
				cmd.Env = append(os.Environ(), "PEERTTY_TEST_ATTACHMENT_FAILURE="+tt.mode)
			}
			conn, err := attach(ctx, tt.addr, cmd)
			if conn != nil {
				conn.Close()
				conn.Release()
				t.Fatal("failure handed out a connection")
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if tt.mode != "missing" && (cmd.ProcessState == nil || !cmd.ProcessState.Exited()) {
				t.Fatal("fixture helper not reaped")
			}
		})
	}
}

func TestAttachmentFailureHelper(t *testing.T) {
	switch os.Getenv("PEERTTY_TEST_ATTACHMENT_FAILURE") {
	case "bad ephemeral port":
		fmt.Fprintln(os.Stdout, "READY 65536")
	case "missing readiness prefix":
		fmt.Fprintln(os.Stdout, "installation in progress")
	case "zero ephemeral port":
		fmt.Fprintln(os.Stdout, "READY 0")
	case "ephemeral guard exits cleanly":
		os.Exit(0)
	case "guard exits":
		fmt.Fprintln(os.Stderr, "fixture startup error")
		os.Exit(2)
	case "guard reports error":
		fmt.Fprintln(os.Stdout, "fixture no service")
	default:
		return
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestActivationNeedsDeadlineBeforeStartingHelper(t *testing.T) {
	conn, err := activate(t.Context(), "127.0.0.1:0")
	if conn != nil || err == nil || !strings.Contains(err.Error(), "授权截止时间") {
		t.Fatalf("activate without deadline = %v, %v", conn, err)
	}
}

type failedReadyWriter struct{ err error }

func (w failedReadyWriter) Write([]byte) (int, error) { return 0, w.err }

func TestGuardReadyWriteFailure(t *testing.T) {
	cause := errors.New("fixture ready pipe broke")
	ports := make(chan int, 1)
	ports <- 43210
	if p, err := peerPort(t.Context(), ports, failedReadyWriter{cause}, "READY"); p != 0 || !errors.Is(err, cause) || len(ports) != 1 {
		t.Fatalf("peerPort = %d, %v, pending ports = %d", p, err, len(ports))
	}
}
