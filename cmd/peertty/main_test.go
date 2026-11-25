package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/identitystate"
	"peertty/internal/localssh"
)

// run writes command results to stdout. Keep these CLI tests serial.
func commandOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = saved }()
	runErr := run(t.Context(), args)
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data)), runErr
}

func TestKeyCommandsReturnTheSameFingerprint(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	generated, err := commandOutput(t, "keygen", "-out", key)
	if err != nil || !grant.ValidFingerprint(generated) {
		t.Fatalf("keygen returned an invalid fingerprint: %v", err)
	}
	if out, err := commandOutput(t, "keygen", "-out", key); !errors.Is(err, os.ErrExist) || out != "" {
		t.Fatalf("duplicate keygen: output %q, error %v", out, err)
	}
	got, err := commandOutput(t, "fingerprint", "-key", key)
	if err != nil || got != generated {
		t.Fatalf("fingerprint changed: %v", err)
	}
	_, err = commandOutput(t, "connect", "-key", key, "-offer", "unused.offer", "-peer", got)
	if err == nil || !strings.Contains(err.Error(), "-answer") {
		t.Fatalf("missing answer: %v", err)
	}
	lease, err := grant.LeaseIdentity(key)
	if err != nil {
		t.Fatalf("failed command retained the role lock: %v", err)
	}
	lease.Close()
}

func TestInformationalCommands(t *testing.T) {
	for _, arg := range []string{"--version", "version"} {
		if out, err := commandOutput(t, arg); err != nil || out != "PeerTTY "+version {
			t.Fatalf("%s: %q, %v", arg, out, err)
		}
	}
	for _, arg := range []string{"help", "--help", "-h"} {
		if out, err := commandOutput(t, arg); err != nil || !strings.Contains(out, "peertty link") {
			t.Fatalf("%s did not list the session commands: %v", arg, err)
		}
	}
	if out, err := commandOutput(t, "doctor", "-stun", "none", "-require-mapping"); err == nil || !strings.Contains(out, "映射候选 0") {
		t.Fatalf("offline diagnostic: %q, %v", out, err)
	}
}

func TestDoctorUsesSelectedProfileAndExplicitOverride(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")
	settings := identitystate.RuntimePath(key, "settings.json")
	write := func(spec string) {
		t.Helper()
		if err := identitystate.Replace(settings, []byte(`{"stun":"`+spec+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	write("none")
	for _, args := range [][]string{{"-state-dir", dir}, {"-key", key}} {
		out, err := commandOutput(t, append([]string{"doctor"}, args...)...)
		if err != nil || !strings.Contains(out, "配置文件 "+settings) || !strings.Contains(out, "STUN 已关闭") {
			t.Fatalf("doctor did not use the selected profile: %q / %v", out, err)
		}
	}
	write("stun:127.0.0.1:3478")
	out, err := commandOutput(t, "doctor", "-key", key, "-stun", "none")
	if err != nil || !strings.Contains(out, "启动参数 -stun") || !strings.Contains(out, "STUN 已关闭") {
		t.Fatalf("explicit offline setting lost: %q / %v", out, err)
	}
	data, err := os.ReadFile(settings)
	if err != nil || !strings.Contains(string(data), "stun:127.0.0.1:3478") {
		t.Fatal("doctor overwrote the saved default", err)
	}
	if _, err := commandOutput(t, "doctor", "-state-dir", dir, "-key", key); err == nil {
		t.Fatal("doctor accepted conflicting profile selectors")
	}
	legacy := t.TempDir()
	if err := os.Mkdir(filepath.Join(legacy, "settings.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := commandOutput(t, "doctor", "-state-dir", legacy, "-stun", "none"); err != nil {
		t.Fatal("explicit STUN unexpectedly depended on the legacy settings file", err)
	}
}

func TestRejectedCLIArguments(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"unknown"}, "unknown command"},
		{[]string{"version", "extra"}, "版本"},
		{[]string{"status", "extra"}, "额外参数"},
		{[]string{"revoke", "extra"}, "额外参数"},
		{[]string{"menu", "-state-dir", "one", "-key", "two"}, "请选择一个"},
		{[]string{"keygen"}, "missing -out"},
		{[]string{"fingerprint"}, "missing -key"},
		{[]string{"host", "-peer", "short"}, "full -peer"},
		{[]string{"connect", "extra"}, "unexpected positional"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			if err := run(t.Context(), tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if err := run(t.Context(), []string{"keygen", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("subcommand help: %v", err)
	}
}

func TestInactiveCLICommands(t *testing.T) {
	state := t.TempDir()
	out, err := commandOutput(t, "status", "-state-dir", state)
	if err != nil || out != active.ErrInactive.Error() {
		t.Fatalf("inactive status: %q, %v", out, err)
	}
	out, err = commandOutput(t, "revoke", "-state-dir", state)
	if !errors.Is(err, active.ErrInactive) || out != "" {
		t.Fatalf("inactive revoke: %q, %v", out, err)
	}
	if _, err := commandOutput(t, "cp", "-state-dir", state, ":/a", "./a"); !errors.Is(err, active.ErrInactive) {
		t.Fatalf("inactive cp: %v", err)
	}
	if _, err := commandOutput(t, "sftp", "-state-dir", state); !errors.Is(err, active.ErrInactive) {
		t.Fatalf("inactive sftp: %v", err)
	}
	for _, sep := range [][]string{nil, {"--"}} {
		args := append([]string{"sftp", "-state-dir", state}, sep...)
		if _, err := commandOutput(t, append(args, "-b", "batch.txt")...); !errors.Is(err, active.ErrInactive) {
			t.Fatalf("native sftp flags did not reach grant lookup: %v", err)
		}
	}
}

func TestApprovalInput(t *testing.T) {
	for _, tc := range []struct {
		name, input, want, wantErr string
	}{
		{name: "path", input: "  my session.answer  \nignored\n", want: "my session.answer"},
		{name: "blank", input: "  \n", wantErr: "session declined"},
		{name: "EOF", wantErr: "session declined"},
		{name: "oversized line", input: strings.Repeat("a", 128*1024), wantErr: "token too long"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "answer")
			if err := os.WriteFile(path, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			in, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			saved := os.Stdin
			os.Stdin = in
			defer func() { os.Stdin = saved }()
			got, err := approval(t.Context())
			if got != tc.want || (tc.wantErr == "" && err != nil) ||
				(tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr))) {
				t.Fatalf("approval = %q, %v; want %q, error containing %q", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestCommandContextStops(t *testing.T) {
	for _, args := range [][]string{nil, {"menu"}, {"connect"}, {"_menu-proxy"}, {"_link-proxy"}} {
		ctx, stop := commandContext(args)
		before := ctx.Err()
		stop()
		if before != nil || !errors.Is(ctx.Err(), context.Canceled) {
			t.Errorf("commandContext(%q): before stop = %v, after = %v", args, before, ctx.Err())
		}
	}
}

func TestCLISessionValidationDoesNotAcquireOrLeakIdentity(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")
	fp, err := grant.NewIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	offer := filepath.Join(dir, "offer")
	for _, tc := range []struct {
		name   string
		args   []string
		cause  error
		wanted string
	}{
		{name: "key required", args: []string{"host", "-offer", offer, "-peer", fp}, wanted: "provide -key"},
		{name: "offer required", args: []string{"host", "-key", key, "-peer", fp}, wanted: "provide -key"},
		{name: "identity file missing", args: []string{"host", "-key", missing, "-offer", offer, "-peer", fp}, cause: os.ErrNotExist},
		{name: "host invalid TTL", args: []string{"host", "-key", key, "-offer", offer, "-peer", fp, "-ttl", "0s"}, wanted: "TTL"},
		{name: "connect offer file missing", args: []string{"connect", "-key", key, "-offer", offer, "-peer", fp, "-answer", filepath.Join(dir, "reply"), "-code-file", missing}, cause: os.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := commandOutput(t, tc.args...); out != "" || err == nil || tc.cause != nil && !errors.Is(err, tc.cause) || tc.wanted != "" && !strings.Contains(err.Error(), tc.wanted) {
				t.Fatalf("output=%q err=%v", out, err)
			}
			lease, err := grant.LeaseIdentity(key)
			if err != nil {
				t.Fatalf("identity remained busy: %v", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(offer); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("created offer before validation: %v", err)
			}
		})
	}
	lease, err := grant.LeaseIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := run(t.Context(), []string{"host", "-key", key, "-offer", offer, "-peer", fp}); !errors.Is(err, grant.ErrInUse) {
		t.Fatalf("did not preserve existing lease: %v", err)
	}
}

func TestCLIDoesNotStartNativeToolsWithoutActiveGrant(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"link", "-state-dir", dir, "-t", "echo fixture"}, active.ErrInactive.Error()},
		{[]string{"link", "-state-dir", dir, "-key", filepath.Join(dir, "key")}, "请选择一个"},
		{[]string{"link", "-unsupported"}, "flag provided but not defined"},
		{[]string{"sftp", "-key=" + filepath.Join(dir, "missing"), "-v"}, active.ErrInactive.Error()},
		{[]string{"fingerprint", "-key", filepath.Join(dir, "missing")}, "missing identity"},
		{[]string{"menu", "-state-dir", dir, "-stun", "none", "-ttl", "0s", "-ssh-port", "2222", "-no-clipboard"}, "SSH 端口或授权时长无效"},
		{[]string{"menu", "-ttl", "invalid"}, "invalid value"},
		{[]string{"doctor", "-stun", "none", "extra"}, "unexpected positional"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			out, err := commandOutput(t, tc.args...)
			matches := err != nil && strings.Contains(err.Error(), tc.want)
			if tc.want == "missing identity" {
				matches = errors.Is(err, os.ErrNotExist)
			}
			if out != "" || !matches {
				t.Fatalf("output=%q err=%v, want %q", out, err, tc.want)
			}
		})
	}
	if err := run(t.Context(), []string{"sftp", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("SFTP help not handled locally: %v", err)
	}
	t.Setenv("PEERTTY_CONSOLE_PROXY", "")
	if err := run(t.Context(), []string{"_menu-proxy"}); err == nil || !strings.Contains(err.Error(), "终端菜单") {
		t.Fatalf("missing menu authorization: %v", err)
	}
}

func TestInternalCLIEntrypointsRejectMissingInvocationContext(t *testing.T) {
	t.Setenv("PEERTTY_LINK_KEY", "")
	t.Setenv("PEERTTY_LINK_ID", "")
	input, err := os.CreateTemp(t.TempDir(), "empty-worker-input")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previous := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previous }()
	if out, err := commandOutput(t, active.Command); err == nil || out == "" {
		t.Fatalf("unconfigured worker did not report its startup error: %q / %v", out, err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"_link-proxy"}, "请使用 peertty link"},
		{[]string{localssh.GuardCommand}, "缺少本机授权截止时间"},
		{[]string{"fingerprint", "extra"}, "unexpected positional arguments"},
		{[]string{"host", "-key", "unused", "-offer", "unused", "-peer", "not-a-fingerprint"}, "full -peer fingerprint"},
	} {
		if out, err := commandOutput(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) || out != "" {
			t.Errorf("%v: got %q / %v; want %q", tc.args, out, err, tc.want)
		}
	}
}

func TestCLIMenuCancellationExitsCleanlyButPreservesSetupErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	key := filepath.Join(t.TempDir(), "fixture.key")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"menu", "-stun", "none", "-key", key}); err != nil {
		t.Fatalf("menu cancellation should be successful: %v", err)
	}
	if err := run(ctx, []string{"menu", "-stun", "none", "-state-dir", filepath.Join(key, "child")}); err == nil {
		t.Fatalf("cancellation incorrectly hid invalid state directory: %v", err)
	}
}

func TestSFTPOptionsPreserveMissingTrailingIdentityValueForFlagParser(t *testing.T) {
	for _, input := range [][]string{{"-key"}, {"--state-dir"}, {"-key", "device.key", "--state-dir"}} {
		flags, native := sftpOptions(input)
		if strings.Join(flags, " ") != strings.Join(input, " ") || len(native) != 0 {
			t.Fatalf("missing option value was routed to native arguments: %v / %v", flags, native)
		}
	}
}
