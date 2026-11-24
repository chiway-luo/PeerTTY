//go:build darwin || linux

package console

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"peertty/internal/active"
	"peertty/internal/localssh"
)

func TestTransferRestoresSharedInputOnExit(t *testing.T) {
	if _, err := localssh.ToolPath("scp"); err != nil {
		t.Skip("OpenSSH command path unavailable")
	}
	for _, closed := range []bool{false, true} {
		name := "transfer interruption"
		if closed {
			name = "closed input is not launched"
		}
		t.Run(name, func(t *testing.T) {
			in, out, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			defer out.Close()
			fd := int(in.Fd())
			if closed {
				if err := in.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var result, diag bytes.Buffer
			state := active.State{ID: "fixture grant"}
			key := filepath.Join(t.TempDir(), "device.key")
			interrupted := errors.New("fixture transfer disconnected")
			called := false
			err = runTransfer(t.Context(), key, state, in, &result, &diag, "scp",
				func(exe string) ([]string, error) {
					if !filepath.IsAbs(exe) {
						t.Fatalf("program path not absolute: %q", exe)
					}
					return []string{"--", "fixture-src", "fixture-dst"}, nil
				}, func(cmd *exec.Cmd) error {
					called = true
					if cmd.Stdin != in || cmd.Stdout != &result || cmd.Stderr != &diag ||
						!slices.Contains(cmd.Env, "PEERTTY_LINK_ID="+state.ID) || !slices.Contains(cmd.Env, "PEERTTY_LINK_KEY="+key) ||
						!slices.Equal(cmd.Args[1:], []string{"--", "fixture-src", "fixture-dst"}) {
						t.Fatal("launcher omitted session, streams or arguments")
					}
					if err := unix.SetNonblock(fd, true); err != nil {
						t.Fatal(err)
					}
					return interrupted
				})
			if closed {
				if called || !errors.Is(err, unix.EBADF) {
					t.Fatalf("closed input: called=%t, err=%v", called, err)
				}
				return
			}
			flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if !called || !errors.Is(err, interrupted) || flagErr != nil || flags&unix.O_NONBLOCK != 0 {
				t.Fatalf("transfer result=%v; launch=%t; input flags=%#x / %v", err, called, flags, flagErr)
			}
		})
	}
}

func TestCopyAndSFTPStopBeforeLaunchWithoutLocalGrant(t *testing.T) {
	key := filepath.Join(t.TempDir(), "no-grant.key")
	for _, err := range []error{
		Copy(t.Context(), key, nil, io.Discard, io.Discard, false, []string{"local", ":/remote"}),
		SFTP(t.Context(), key, nil, io.Discard, io.Discard, nil),
	} {
		if err == nil {
			t.Fatal("transfer ran without an active grant")
		}
	}
}
