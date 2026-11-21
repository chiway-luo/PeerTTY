package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if out, err := commandOutput(t, "doctor", "-stun", "none", "-require-mapping"); err == nil || !strings.Contains(out, "STUN 映射 0") {
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
