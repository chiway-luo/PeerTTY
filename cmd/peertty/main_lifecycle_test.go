package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func TestCLIExitPreservesNativeStatusOnlyForSSHAndTransferCommands(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestCLIExitFixture$")
	cmd.Env = append(os.Environ(), "PEERTTY_TEST_MAIN_EXIT=42")
	childErr := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(childErr, &exit) || exit.ExitCode() != 42 {
		t.Fatalf("fixture did not exit with 42: %v", childErr)
	}
	wrapped := fmt.Errorf("fixture wrapper: %w", childErr)
	for _, tc := range []struct {
		command string
		err     error
		code    int
		text    bool
	}{
		{"", nil, 0, false},
		{"menu", fmt.Errorf("fixture help: %w", flag.ErrHelp), 0, false},
		{"", wrapped, 1, true},
		{"doctor", wrapped, 1, true},
		{"link", wrapped, 42, false},
		{"cp", wrapped, 42, false},
		{"sftp", wrapped, 42, false},
		{"link", errors.New("fixture launch failed"), 1, true},
		{"cp", &exec.ExitError{}, 1, true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			var diag bytes.Buffer
			var args []string
			if tc.command != "" {
				args = []string{tc.command}
			}
			code := exitCode(args, tc.err, &diag)
			if code != tc.code || (diag.Len() != 0) != tc.text || tc.text && !strings.HasPrefix(diag.String(), "peertty: ") {
				t.Fatalf("exit status or diagnostic changed: %d / %q", code, diag.String())
			}
		})
	}
}

func TestCLIExitFixture(t *testing.T) {
	if os.Getenv("PEERTTY_TEST_MAIN_EXIT") == "42" {
		os.Exit(42)
	}
}

func TestProxyDrainStopsOnlyAfterGraceOrExplicitCancellation(t *testing.T) {
	for _, phase := range []string{"before SIGHUP", "during grace", "grace expired"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const grace = 12 * time.Second
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				hup := make(chan os.Signal, 1)
				done := make(chan struct{})
				go func() {
					defer close(done)
					waitProxyDrain(ctx, hup, grace, cancel)
				}()
				synctest.Wait()
				if phase == "before SIGHUP" {
					cancel()
				} else {
					hup <- syscall.SIGHUP
					synctest.Wait()
					time.Sleep(grace - time.Second)
					if ctx.Err() != nil {
						t.Fatal("normal SSH exit interrupted draining early")
					}
					if phase == "during grace" {
						cancel()
					} else {
						time.Sleep(time.Second)
					}
				}
				<-done
				if !errors.Is(ctx.Err(), context.Canceled) {
					t.Fatalf("proxy remained alive past its drain window: %v", ctx.Err())
				}
			})
		})
	}
}
