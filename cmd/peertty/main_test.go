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
