package console

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
)

func TestFileTransferArgumentBoundaries(t *testing.T) {
	s := active.State{User: "operator", Alias: "example-device", KnownHosts: "known hosts"}
	for _, c := range []struct {
		name      string
		paths     []string
		recursive bool
		last      []string
	}{
		{"download", []string{"remote:/logs/a", "./local"}, false, []string{"operator@example-device:/logs/a", "./local"}},
		{"upload", []string{"./local", ":/logs"}, true, []string{"./local", "operator@example-device:/logs"}},
		{"missing target", []string{":/logs"}, false, nil},
		{"local only", []string{"./a", "./b"}, false, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			args, err := scpArgs("peertty", s, c.recursive, c.paths)
			if c.last == nil {
				if err == nil || args != nil {
					t.Fatalf("accepted invalid paths: %q, %v", args, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := append([]string{"--"}, c.last...)
			if len(args) < len(want) || !slices.Equal(args[len(args)-len(want):], want) || slices.Contains(args, "-r") != c.recursive ||
				!slices.Contains(args, "StrictHostKeyChecking=yes") {
				t.Fatalf("unexpected scp args: %q", args)
			}
		})
	}
}

func TestSFTPArgumentValidation(t *testing.T) {
	s := active.State{User: "operator", Alias: "example-device", SSHConfig: "fixture.conf", Identity: "fixture.key"}
	for _, c := range []struct {
		name    string
		extra   []string
		tail    []string
		errText string
	}{
		{"defaults", nil, []string{"--", "operator@example-device"}, ""},
		{"flags and attached value", []string{"-qv", "-R4", "--"}, []string{"-qv", "-R4", "--", "operator@example-device"}, ""},
		{"separate value", []string{"-R", "4"}, []string{"-R", "4", "--", "operator@example-device"}, ""},
		{"missing value", []string{"-R"}, nil, "缺少参数"},
		{"empty value", []string{"-R", ""}, nil, "缺少参数"},
		{"unaccepted option", []string{"-Z"}, nil, "不支持"},
		{"not an option", []string{"elsewhere"}, nil, "当前授权指定"},
		{"bare hyphen", []string{"-"}, nil, "当前授权指定"},
	} {
		t.Run(c.name, func(t *testing.T) {
			args, err := sftpArgs("peertty", s, c.extra)
			if c.errText != "" {
				if err == nil || args != nil || !strings.Contains(err.Error(), c.errText) {
					t.Fatalf("args %q error %v", args, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(args) < len(c.tail) || !slices.Equal(args[len(args)-len(c.tail):], c.tail) ||
				!slices.Contains(args, "fixture.conf") || !slices.Contains(args, "fixture.key") {
				t.Fatalf("args %q", args)
			}
		})
	}
}

func TestFileTransferRequiresLiveControlGrant(t *testing.T) {
	diagnostic := errors.New("worker unavailable")
	for _, tc := range []struct {
		name, role, phase, want, reconnect string
		statusErr                          error
	}{
		{name: "ready", role: "control", phase: "ready"},
		{name: "host is not a transfer authorization", role: "host", phase: "ready", want: "尚无已连接"},
		{name: "wait for approval", role: "control", phase: "waiting", want: "尚无已连接"},
		{name: "offline displays the diagnostic", role: "control", phase: "offline", want: "fixture disconnect reason"},
		{name: "recovered original transfer", role: "control", phase: "disconnected", reconnect: "ready"},
		{name: "revoked while reconnecting", role: "control", phase: "disconnected", reconnect: "replacement", want: "授权已结束"},
		{name: "status unavailable", statusErr: diagnostic, want: diagnostic.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := active.State{ID: "selected", Role: tc.role, Phase: tc.phase, Note: "fixture disconnect reason", Deadline: time.Now().Add(time.Minute)}
			var out bytes.Buffer
			statusCalls, waitCalls := 0, 0
			got, err := resolveTransferGrantWith(t.Context(), &out,
				func(context.Context) (active.State, error) { statusCalls++; return st, tc.statusErr },
				func(ctx context.Context, selected active.State, w io.Writer) (active.State, error) {
					waitCalls++
					if selected.ID != st.ID {
						t.Fatal("waited for a different grant")
					}
					return waitReconnect(ctx, selected, w, reconnectTicks(1), func(context.Context) (active.State, error) {
						fresh := st
						fresh.Phase = "ready"
						if tc.reconnect == "replacement" {
							fresh.ID = "not selected"
						}
						return fresh, nil
					})
				})
			if tc.want == "" {
				if err != nil || got.ID != st.ID || got.Phase != "ready" {
					t.Fatalf("incorrect transfer state: %+v %v", got, err)
				}
			} else if got.ID != "" || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("incorrect transfer rejection: %+v %v; want %q", got, err, tc.want)
			}
			if statusCalls != 1 || (waitCalls == 1) != (tc.reconnect != "") {
				t.Fatalf("calls: status %d wait %d", statusCalls, waitCalls)
			}
			if strings.Contains(out.String(), reconnectNotice) != (tc.reconnect != "") {
				t.Fatalf("misleading reconnect output: %q", out.String())
			}
		})
	}
}

func TestTransferChecksArgumentsAndToolBeforeLaunching(t *testing.T) {
	argErr := errors.New("invalid transfer args")
	var launched bool
	run := func(*exec.Cmd) error { launched = true; return nil }
	st := active.State{ID: "fixture"}
	if err := runTransfer(t.Context(), "fixture.key", st, nil, io.Discard, io.Discard, "scp",
		func(string) ([]string, error) { return nil, argErr }, run); !errors.Is(err, argErr) || launched {
		t.Fatalf("invalid arguments reached launcher: %v", err)
	}
	const missing = "peertty-nonexistent-openssh-fixture"
	if err := runTransfer(t.Context(), "fixture.key", st, nil, io.Discard, io.Discard, missing,
		func(string) ([]string, error) { return []string{"--"}, nil }, run); err == nil || launched || !strings.Contains(err.Error(), missing) {
		t.Fatalf("unavailable tool reached launcher: %v", err)
	}
}

func TestCopyKeepsLocalColonFilenameAnOrdinaryArgument(t *testing.T) {
	filename := "build:nightly.log"
	args, err := scpArgs("fixture", active.State{User: "operator", Alias: "host-fixture"}, false, []string{filename, ":/reports"})
	want := []string{"--", "." + string(filepath.Separator) + filename, "operator@host-fixture:/reports"}
	if err != nil || len(args) < len(want) || !slices.Equal(args[len(args)-len(want):], want) {
		t.Fatalf("copy args %q / %v, want suffix %q", args, err, want)
	}
}
