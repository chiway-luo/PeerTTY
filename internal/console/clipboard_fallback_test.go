package console

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"peertty/internal/grant"
)

func TestClipboardNativeReadReportsResultWithoutLaunchingHelper(t *testing.T) {
	ticket := grant.Ticket{Claims: grant.Claims{SDP: "local fixture"}}
	var encoded bytes.Buffer
	if err := writeTicketText(&encoded, ticket); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, input, text, wantError string
		nativeErr                    error
		read                         bool
	}{
		{name: "clipboard action not requested", input: "./fixture.offer"},
		{name: "complete clipboard ticket", input: "/paste", text: encoded.String(), read: true},
		{name: "non-ticket text", input: "p", text: "not a ticket", wantError: "没有完整", read: true},
		{name: "partial clipboard ticket", input: "p", text: ticketBegin + "\n", wantError: "不完整", read: true},
		{name: "oversize native read", input: "p", nativeErr: oversizePaste, wantError: "超过长度限制", read: true},
		{name: "native read unavailable", input: "p", nativeErr: errors.New("fixture resource busy"), wantError: "无法读取系统剪贴板", read: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			text, err := ticketInputUsing(t.Context(), tt.input, func() (string, bool, error) {
				calls++
				return tt.text, true, tt.nativeErr
			}, func(context.Context, bool) (*exec.Cmd, error) {
				t.Fatal("native read should not launch a helper")
				return nil, nil
			})
			if (calls == 1) != tt.read || calls > 1 {
				t.Fatalf("unexpected native read count: %d", calls)
			}
			if tt.wantError != "" {
				if text != "" || err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("read = %q / %v; want error containing %q", text, err, tt.wantError)
				}
				if errors.Is(tt.nativeErr, oversizePaste) && !errors.Is(err, oversizePaste) {
					t.Fatal("lost oversize classification")
				}
			} else if !tt.read {
				if text != tt.input || err != nil {
					t.Fatalf("literal input = %q / %v", text, err)
				}
			} else {
				got, parseErr := readTicket(text)
				if err != nil || parseErr != nil || got.Claims.SDP != ticket.Claims.SDP {
					t.Fatalf("ticket result %q / %v / %v", text, err, parseErr)
				}
			}
		})
	}
}

type rejectingClipboardWriter struct{ err error }

func (w rejectingClipboardWriter) Write([]byte) (int, error) { return 0, w.err }

func TestClipboardTerminalFallbackNeverClaimsConfirmedCopy(t *testing.T) {
	ticket := grant.Ticket{Claims: grant.Claims{SDP: "terminal fixture"}}
	lookup := func(context.Context, bool) (*exec.Cmd, error) { return nil, exec.ErrNotFound }
	var out bytes.Buffer
	status, err := copyTicketWithTerminal(t.Context(), &out, ticket, lookup, func() bool { return true })
	if err != nil || !strings.Contains(status, "是否写入取决于") || strings.HasPrefix(status, "已复制") {
		t.Fatalf("unconfirmed terminal copy = %q / %v", status, err)
	}
	data, ok := strings.CutPrefix(out.String(), "\x1b]52;c;")
	data, end := strings.CutSuffix(data, "\x07")
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil || !ok || !end {
		t.Fatalf("invalid fallback frame in local fixture: %v", err)
	}
	got, err := readTicket(strings.TrimSpace(string(decoded)))
	if err != nil || got.Claims.SDP != ticket.Claims.SDP {
		t.Fatalf("wrong fallback ticket: %v", err)
	}
	want := errors.New("fixture terminal output failed")
	status, err = copyTicketWithTerminal(t.Context(), rejectingClipboardWriter{want}, ticket, lookup, func() bool { return true })
	if status != "" || !errors.Is(err, want) {
		t.Fatalf("lost fallback write error: %q / %v", status, err)
	}
}

func TestClipboardNativeWriteFallsBackOnlyWhenNeeded(t *testing.T) {
	ticket := grant.Ticket{Claims: grant.Claims{SDP: "clipboard fixture"}}
	backendErr := errors.New("fixture clipboard backend missing")
	for _, tc := range []struct {
		name      string
		handled   bool
		nativeErr error
		fallback  bool
	}{
		{"native success", true, nil, false},
		{"native unavailable", false, nil, true},
		{"native error", true, errors.New("fixture clipboard busy"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var out bytes.Buffer
			status, err := copyTicketUsing(t.Context(), &out, ticket, func(data string) (bool, error) {
				roundTrip, err := readTicket(strings.TrimSpace(data))
				if err != nil || roundTrip.Claims.SDP != ticket.Claims.SDP {
					t.Fatalf("unexpected native payload: %v", err)
				}
				return tc.handled, tc.nativeErr
			}, func(_ context.Context, write bool) (*exec.Cmd, error) {
				calls++
				if !write {
					t.Error("write unexpectedly requested a read helper")
				}
				return nil, backendErr
			})
			if (calls == 1) != tc.fallback || calls > 1 || out.Len() != 0 {
				t.Fatalf("unexpected terminal output or helper calls: %q / %d", out.String(), calls)
			}
			if tc.fallback {
				if status != "" || !errors.Is(err, backendErr) {
					t.Fatalf("fallback result = %q / %v", status, err)
				}
			} else if err != nil || !strings.HasPrefix(status, "已复制") {
				t.Fatalf("native result = %q / %v", status, err)
			}
		})
	}
}

func TestClipboardTerminalEligibility(t *testing.T) {
	for _, tc := range []struct {
		name, platform, term string
		terminal, want       bool
	}{
		{"windows uses native clipboard", "windows", "xterm", true, false},
		{"redirected output", "linux", "xterm", false, false},
		{"missing terminal name", "linux", "", true, false},
		{"dumb terminal", "darwin", "dumb", true, false},
		{"interactive terminal", "darwin", "xterm-256color", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := terminalClipboardAvailable(tc.platform, func() bool {
				if tc.platform == "windows" {
					t.Error("Windows should not inspect its output stream")
				}
				return tc.terminal
			}, tc.term)
			if got != tc.want {
				t.Fatalf("terminal fallback = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestClipboardNativeReadFallsBackWhenUnhandled(t *testing.T) {
	want := errors.New("fixture fallback unavailable")
	result, err := ticketInputUsing(t.Context(), "/paste", func() (string, bool, error) {
		return "not a native result", false, nil
	}, func(_ context.Context, write bool) (*exec.Cmd, error) {
		if write {
			t.Error("read unexpectedly requested a write helper")
		}
		return nil, want
	})
	if result != "" || !errors.Is(err, want) {
		t.Fatalf("fallback result = %q / %v", result, err)
	}
}
