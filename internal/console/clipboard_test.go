package console

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"peertty/internal/grant"
)

func TestShareTicketKeepsTextAvailableWhenCopyIsNotConfirmed(t *testing.T) {
	ticket := grant.Ticket{Claims: grant.Claims{SDP: "clipboard fixture"}}
	for _, tc := range []struct {
		name, kind, status string
		copyErr            error
		copyOn, show, text bool
	}{
		{"disabled", "邀请", "", nil, false, false, false},
		{"explicit text", "邀请", "", nil, false, true, true},
		{"system copied", "回执", "已复制到系统剪贴板。", nil, true, false, false},
		{"terminal copy unconfirmed", "回执", "已向终端发送复制请求", nil, true, false, true},
		{"failed copy", "邀请", "", errors.New("fixture copy failure"), true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			calls := 0
			copy := func(_ context.Context, _ io.Writer, got grant.Ticket) (string, error) {
				calls++
				if got.Claims.SDP != ticket.Claims.SDP {
					t.Fatal("copied the wrong ticket")
				}
				return tc.status, tc.copyErr
			}
			if err := shareTicketWith(t.Context(), &out, tc.kind, ticket, tc.copyOn, tc.show, copy); err != nil {
				t.Fatal(err)
			}
			if (calls == 1) != tc.copyOn || strings.Contains(out.String(), ticketBegin) != tc.text {
				t.Fatalf("copy calls = %d; transcript = %q", calls, out.String())
			}
		})
	}
}

func TestClipboardCommandFailuresDoNotUseSystemClipboard(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-clipboard")
	bad := errors.New("no fixture clipboard")
	ticket := grant.Ticket{Claims: grant.Claims{SDP: "clipboard fixture"}}
	if _, err := copyTicketWith(t.Context(), io.Discard, ticket, func(context.Context, bool) (*exec.Cmd, error) { return nil, bad }); !errors.Is(err, bad) {
		t.Fatalf("copy without backend: %v", err)
	}
	if _, err := ticketInputWith(t.Context(), "/paste", func(context.Context, bool) (*exec.Cmd, error) { return nil, bad }); !errors.Is(err, bad) {
		t.Fatalf("read without backend: %v", err)
	}
	if _, err := ticketInputWith(t.Context(), "p", func(ctx context.Context, write bool) (*exec.Cmd, error) {
		if write {
			t.Fatal("read requested write command")
		}
		return exec.CommandContext(ctx, missing), nil
	}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unlaunchable read command: %v", err)
	}
}

func TestClipboardBackendWithIsolatedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture")
	}
	dir := t.TempDir()
	bufPath := filepath.Join(dir, "clipboard")
	lookup := func(ctx context.Context, write bool) (*exec.Cmd, error) {
		if write {
			return exec.CommandContext(ctx, "/bin/sh", "-c", `cat > "$1"`, "test", bufPath), nil
		}
		return exec.CommandContext(ctx, "/bin/sh", "-c", `cat "$1"`, "test", bufPath), nil
	}
	ticket := grant.Ticket{Claims: grant.Claims{SDP: "fixture"}}
	if got, err := copyTicketWith(t.Context(), io.Discard, ticket, lookup); err != nil || !strings.HasPrefix(got, "已复制") {
		t.Fatalf("copy to fixture: %q, %v", got, err)
	}
	text, err := ticketInputWith(t.Context(), "/paste", lookup)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readTicket(text)
	if err != nil || got.Claims.SDP != ticket.Claims.SDP {
		t.Fatalf("round trip: %v, %v", got, err)
	}
	for _, tc := range []struct {
		name, input string
		want        string
	}{
		{"plain text", "not a ticket", "没有完整"},
		{"incomplete", ticketBegin + "\n", "不完整"},
		{"oversized", strings.Repeat("a", maxPaste+1), "超过长度限制"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(bufPath, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ticketInputWith(t.Context(), "/paste", lookup); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("import error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestClipboardCommandForMacUsesPlatformToolsWithoutExecutingThem(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin command selection")
	}
	for _, tc := range []struct {
		copy bool
		want []string
	}{
		{true, []string{"/usr/bin/pbcopy"}},
		{false, []string{"/usr/bin/pbpaste", "-Prefer", "txt"}},
	} {
		cmd, err := clipboardCommand(t.Context(), tc.copy)
		if err != nil || !slices.Equal(cmd.Args, tc.want) {
			t.Fatalf("copy=%v: command=%v err=%v", tc.copy, cmd, err)
		}
	}
}

func TestClipboardReadPropagatesPipeAndProcessFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	_, err := ticketInputWith(t.Context(), "p", func(ctx context.Context, write bool) (*exec.Cmd, error) {
		if write {
			t.Fatal("read asked for unexpected copy")
		}
		cmd := exec.CommandContext(ctx, path)
		cmd.Stdout = io.Discard
		return cmd, nil
	})
	if err == nil || !strings.Contains(err.Error(), "Stdout already set") {
		t.Fatalf("pipe error=%v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	value, err := ticketInputWith(t.Context(), "p", func(ctx context.Context, _ bool) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1"), nil
	})
	if value != "" || err == nil || !strings.Contains(err.Error(), "无法读取系统剪贴板") {
		t.Fatalf("process error: %q / %v", value, err)
	}
	value, err = ticketInputWith(t.Context(), "./invitation", func(context.Context, bool) (*exec.Cmd, error) {
		t.Fatal("literal path must not access clipboard")
		return nil, nil
	})
	if err != nil || value != "./invitation" {
		t.Fatalf("literal input changed: %q / %v", value, err)
	}
}
