//go:build darwin || linux

package console

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"strings"
	"testing"
	"time"

	"peertty/internal/active"
)

func isolatedSSHClient(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestCLIGrantActionsRejectInactiveOrUnreadableStatus(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	var out bytes.Buffer
	if err := Link(t.Context(), key, nil, &out, &out, RemoteCommand{}); !errors.Is(err, active.ErrInactive) {
		t.Fatalf("link without grant = %v", err)
	}
	if err := EndGrant(t.Context(), key, &out); !errors.Is(err, active.ErrInactive) {
		t.Fatalf("revoke without grant = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("failed actions wrote %q", out.String())
	}
	if err := os.WriteFile(key+".active", []byte("not a port"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := DisplayStatus(t.Context(), key, &out); err == nil || errors.Is(err, active.ErrInactive) || out.Len() != 0 {
		t.Fatalf("unreadable status = %v, output = %q", err, out.String())
	}
}

func TestStatusIncludesDirectRouteWithoutManufacturingNote(t *testing.T) {
	var out bytes.Buffer
	printStatus(&out, active.State{Role: "control", Phase: "ready", Route: "fixture-route", Deadline: time.Now().Add(-time.Hour)})
	if got := out.String(); !strings.Contains(got, "剩余 0s") || !strings.HasSuffix(got, "直连路径  fixture-route\n") {
		t.Fatalf("status = %q", got)
	}
}

func TestLinkRefusesOfflineOrExpiredGrantBeforeLaunching(t *testing.T) {
	for _, tc := range []struct {
		name, phase, note string
		want              error
	}{
		{"offline", "offline", "fixture: peer unavailable", nil},
		{"expired during reconnect", "disconnected", "", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := active.State{Role: "control", Phase: tc.phase, Note: tc.note, Deadline: time.Now().Add(-time.Second)}
			var diag bytes.Buffer
			err := linkSSH(t.Context(), "", s, nil, io.Discard, &diag, RemoteCommand{}, func(*exec.Cmd) error {
				t.Fatal("launched SSH without a ready grant")
				return nil
			})
			if tc.want != nil {
				if !errors.Is(err, tc.want) || !strings.Contains(diag.String(), reconnectNotice) {
					t.Fatalf("expiry = %v, diagnostic = %q", err, diag.String())
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.note) {
				t.Fatalf("offline = %v", err)
			}
		})
	}
}

func TestLinkDoesNotLaunchWithClosedInput(t *testing.T) {
	isolatedSSHClient(t, "exit 0")
	in, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	s := active.State{Role: "control", Phase: "ready"}
	if err := linkSSH(t.Context(), "", s, in, io.Discard, io.Discard, RemoteCommand{}, func(*exec.Cmd) error {
		t.Fatal("launched SSH despite failed input setup")
		return nil
	}); err == nil {
		t.Fatal("expected closed input error")
	}
}

func TestInteractiveLinkReportsEndedGrantAfterClientExit(t *testing.T) {
	isolatedSSHClient(t, "exit 42")
	in, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	s := active.State{Role: "control", Phase: "ready", ID: "ended", Alias: "fixture", User: "operator"}
	var out bytes.Buffer
	c := Console{in: in, out: &out, Settings: Settings{KeyPath: filepath.Join(t.TempDir(), "device.key")}}
	err = c.linkSSH(t.Context(), s)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 || !strings.Contains(err.Error(), "本次授权已结束") {
		t.Fatalf("missing grant ending or original exit status: %v", err)
	}
}

func TestProxyRequiresAnAbsoluteIdentityAndSelectedGrant(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "device.key")
	for _, tc := range []struct{ key, id, want string }{
		{"device.key", "fixture", "请使用 peertty link"},
		{abs, "", "请使用 peertty link"},
		{abs, "fixture", active.ErrInactive.Error()},
	} {
		t.Setenv("PEERTTY_LINK_KEY", tc.key)
		t.Setenv("PEERTTY_LINK_ID", tc.id)
		err := LinkProxy(t.Context(), strings.NewReader(""), io.Discard)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("proxy input %q / %q: %v", tc.key, tc.id, err)
		}
	}
}

func TestTransferStubAllowsNoInputAndRefusesClosedInput(t *testing.T) {
	isolatedSSHClient(t, "exit 0")
	in, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	s := active.State{ID: "selected"}
	key := filepath.Join(t.TempDir(), "device.key")
	build := func(string) ([]string, error) { return []string{"fixture"}, nil }
	var calls int
	run := func(cmd *exec.Cmd) error {
		calls++
		for _, value := range []string{"PEERTTY_LINK_ID=" + s.ID, "PEERTTY_LINK_KEY=" + key} {
			if !slices.Contains(cmd.Env, value) {
				t.Errorf("missing selected grant binding %q", value)
			}
		}
		return nil
	}
	if err := runTransfer(t.Context(), key, s, nil, io.Discard, io.Discard, "ssh", build, run); err != nil || calls != 1 {
		t.Fatalf("transfer without stdin: %v, calls=%d", err, calls)
	}
	if err := runTransfer(t.Context(), key, s, in, io.Discard, io.Discard, "ssh", build, run); err == nil || calls != 1 {
		t.Fatalf("closed stdin reached launcher: %v, calls=%d", err, calls)
	}
}

func TestLinkExitPreservesGrantAndOpenSSHStatus(t *testing.T) {
	ctx := t.Context()
	exit255 := exec.CommandContext(ctx, "/bin/sh", "-c", "exit 255").Run()
	var exit *exec.ExitError
	if !errors.As(exit255, &exit) || exit.ExitCode() != 255 {
		t.Fatalf("local exit fixture: %v", exit255)
	}
	original := errors.New("fixture terminal failure")
	for _, tc := range []struct {
		name, phase, id, note, want string
		startErr, statusErr         error
		reconnecting                bool
	}{
		{name: "ended grant", startErr: original, statusErr: active.ErrInactive, want: "本次授权已结束"},
		{name: "replaced grant", startErr: original, phase: "ready", id: "replacement", want: "本次授权已结束"},
		{name: "same grant reconnecting", startErr: original, phase: "disconnected", id: "selected", reconnecting: true},
		{name: "offline reason retained", startErr: original, phase: "offline", id: "selected", note: "fixture backend ended", want: "fixture backend ended"},
		{name: "same grant ready after transport interruption", startErr: exit255, phase: "ready", id: "selected", want: "直连仍可用，但 SSH 登录未完成或终端已断开"},
		{name: "non transport error", startErr: original, phase: "ready", id: "selected"},
		{name: "temporary status unavailable", startErr: exit255, statusErr: io.ErrUnexpectedEOF},
		{name: "no stable status to report", startErr: original, phase: "connecting", id: "selected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fresh := active.State{ID: tc.id, Phase: tc.phase, Note: tc.note}
			got := describeLinkExit("selected", tc.startErr, fresh, tc.statusErr)
			if tc.reconnecting {
				var pending reconnectingGrant
				if !errors.As(got, &pending) || pending.id != "selected" {
					t.Fatalf("did not return reconnecting state for the existing grant: %v", got)
				}
			} else if tc.want != "" {
				if !errors.Is(got, tc.startErr) || !strings.Contains(got.Error(), tc.want) {
					t.Fatalf("lost original error or expected explanation %q: %v", tc.want, got)
				}
			} else if got != tc.startErr {
				t.Fatalf("rewrote original error when the status did not explain it: %v", got)
			}
		})
	}
}

func TestReadyInteractiveLinkHonorsCancellationWithoutReclassifyingExit(t *testing.T) {
	isolatedSSHClient(t, "exit 42")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	in, err := os.CreateTemp(t.TempDir(), "terminal")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	tui := Console{in: in, out: io.Discard, Settings: Settings{KeyPath: filepath.Join(t.TempDir(), "device.key")}}
	s := active.State{ID: "selected", Role: "control", Phase: "ready", User: "test", Alias: "fixture"}
	if err := tui.linkSSH(ctx, s); !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "授权已结束") {
		t.Fatalf("cancellation was reclassified: %v", err)
	}
}

func TestReadyInteractiveLinkShowsSSHLoginBeforeNativeOutput(t *testing.T) {
	isolatedSSHClient(t, "printf 'native SSH output\\n'")
	in, err := os.CreateTemp(t.TempDir(), "terminal")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out bytes.Buffer
	tui := Console{in: in, out: &out, fullScreen: true, Settings: Settings{KeyPath: filepath.Join(t.TempDir(), "device.key")}}
	s := active.State{ID: "selected", Role: "control", Phase: "ready", User: "test", Alias: "fixture"}
	if err := tui.linkSSH(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	visible := out.String()
	notice, sshOutput := strings.Index(visible, leaveScreen+erasePage+sshLoginNotice), strings.Index(visible, "native SSH output")
	if notice < 0 || sshOutput <= notice {
		t.Fatalf("SSH login notice is not visible before native output: %q", visible)
	}
}
