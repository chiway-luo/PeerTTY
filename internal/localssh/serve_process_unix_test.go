//go:build darwin || linux

package localssh

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type localChildNotice func([]byte) (int, error)

func (w localChildNotice) Write(p []byte) (int, error) { return w(p) }

func TestLocalSSHChildReportsAttachmentAndReapsWithoutRunningSSHD(t *testing.T) {
	for _, tc := range []struct {
		name, script, notice string
		exit                 int
		missing, cancel      bool
		writeErr             error
	}{
		{name: "clean child exit", script: "exit 0", notice: "ATTACHED\n"},
		{name: "normal client disconnect", script: "exit 255", notice: "ATTACHED\n"},
		{name: "non-disconnect error survives", script: "exit 23", notice: "ATTACHED\n", exit: 23},
		{name: "cancellation after attachment", script: "exit 23", notice: "ATTACHED\n", cancel: true},
		{name: "failed notification", script: "exit 0", notice: "ATTACHED\n", writeErr: io.ErrClosedPipe},
		{name: "binary missing", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			socket, err := os.CreateTemp(t.TempDir(), "fixture-descriptor")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = socket.Close() })
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", tc.script)
			if tc.missing {
				cmd = exec.CommandContext(ctx, filepath.Join(t.TempDir(), "missing-fixture"))
			}
			var received strings.Builder
			out := localChildNotice(func(p []byte) (int, error) {
				n, _ := received.Write(p)
				if tc.cancel {
					cancel()
				}
				if tc.writeErr != nil {
					return 0, tc.writeErr
				}
				return n, nil
			})
			err = runLocalSSHD(ctx, cmd, socket, out)
			var exit *exec.ExitError
			switch {
			case tc.missing:
				if !errors.Is(err, os.ErrNotExist) || cmd.Process != nil {
					t.Fatalf("failed start = %v, process = %v", err, cmd.Process)
				}
			case tc.writeErr != nil:
				if !errors.Is(err, tc.writeErr) {
					t.Fatalf("lost attachment error: %v", err)
				}
			case tc.exit != 0:
				if !errors.As(err, &exit) || exit.ExitCode() != tc.exit {
					t.Fatalf("lost child exit %d: %v", tc.exit, err)
				}
			case err != nil:
				t.Fatalf("unexpected child error: %v", err)
			}
			if got := received.String(); got != tc.notice {
				t.Fatalf("notification = %q, want %q", got, tc.notice)
			}
			if !tc.missing && (cmd.ProcessState == nil || !tc.cancel && tc.writeErr == nil && !cmd.ProcessState.Exited()) {
				t.Fatalf("child not reaped: %v", cmd.ProcessState)
			}
			if _, e := socket.Stat(); !errors.Is(e, os.ErrClosed) {
				t.Fatalf("descriptor not closed: %v", e)
			}
		})
	}
}
