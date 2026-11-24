package console

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"peertty/internal/grant"
)

func clipboardChoice(s string) bool {
	return strings.EqualFold(s, "p") || s == "/paste"
}

func (t *Console) shareTicket(ctx context.Context, kind string, ticket grant.Ticket, copyOn, show bool) error {
	copy := t.copyToClipboard
	if copy == nil {
		copy = copyTicket
	}
	return shareTicketWith(ctx, t.pageOut(), kind, ticket, copyOn, show, copy)
}

func shareTicketWith(ctx context.Context, out io.Writer, kind string, ticket grant.Ticket, copyOn, show bool, copy func(context.Context, io.Writer, grant.Ticket) (string, error)) error {
	if copyOn {
		status, err := copy(ctx, out, ticket)
		if err == nil {
			fmt.Fprintln(out, kind+" · "+status)
			if !strings.HasPrefix(status, "已复制") && kind == "回执" {
				show = true
			}
		} else {
			fmt.Fprintln(out, err)
			show = true
		}
	}
	if show {
		fmt.Fprintln(out, kind+"文本")
		return writeTicketText(out, ticket)
	}
	return nil
}

func clipboardCommand(ctx context.Context, write bool) (*exec.Cmd, error) {
	return clipboardCommandFor(ctx, write, runtime.GOOS, os.Getenv, exec.LookPath)
}

func clipboardCommandFor(ctx context.Context, write bool, platform string, getenv func(string) string, lookPath func(string) (string, error)) (*exec.Cmd, error) {
	switch platform {
	case "darwin":
		if write {
			return exec.CommandContext(ctx, "/usr/bin/pbcopy"), nil
		}
		return exec.CommandContext(ctx, "/usr/bin/pbpaste", "-Prefer", "txt"), nil
	case "windows":
		exe := windowsPowerShellPath()
		script := "[Console]::Write((Get-Clipboard -Raw -ErrorAction Stop))"
		if write {
			script = "Set-Clipboard -Value ([Console]::In.ReadToEnd()) -ErrorAction Stop"
		}
		return exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-STA", "-Command", script), nil
	case "linux":
		if getenv("WAYLAND_DISPLAY") != "" {
			name := "wl-paste"
			args := []string{"--no-newline"}
			if write {
				name, args = "wl-copy", nil
			}
			if exe, err := lookPath(name); err == nil {
				return exec.CommandContext(ctx, exe, args...), nil
			}
		}
		if getenv("DISPLAY") != "" {
			if exe, err := lookPath("xclip"); err == nil {
				mode := "-out"
				if write {
					mode = "-in"
				}
				return exec.CommandContext(ctx, exe, "-selection", "clipboard", mode), nil
			}
			if exe, err := lookPath("xsel"); err == nil {
				mode := "--output"
				if write {
					mode = "--input"
				}
				return exec.CommandContext(ctx, exe, "--clipboard", mode), nil
			}
		}
	}
	return nil, errors.New("当前没有可用的系统剪贴板")
}

// A remote terminal can accept an OSC 52 copy request even on a headless host.
// Its clipboard policy is local to the terminal, so success is not assumed.
type clipboardLookup func(context.Context, bool) (*exec.Cmd, error)

func copyTicket(parent context.Context, out io.Writer, ticket grant.Ticket) (string, error) {
	return copyTicketUsing(parent, out, ticket, nativeWriteClipboard, clipboardCommand)
}

func copyTicketUsing(parent context.Context, out io.Writer, ticket grant.Ticket, native func(string) (bool, error), lookup clipboardLookup) (string, error) {
	var b strings.Builder
	if err := writeTicketText(&b, ticket); err != nil {
		return "", err
	}
	if handled, err := native(b.String()); handled && err == nil {
		return "已复制到系统剪贴板。", nil
	}
	return copyTicketWith(parent, out, ticket, lookup)
}

func copyTicketWith(parent context.Context, out io.Writer, ticket grant.Ticket, lookup clipboardLookup) (string, error) {
	return copyTicketWithTerminal(parent, out, ticket, lookup, func() bool {
		return terminalClipboardAvailable(runtime.GOOS, func() bool { return terminalFile(out) }, os.Getenv("TERM"))
	})
}

func terminalClipboardAvailable(platform string, isTerminal func() bool, term string) bool {
	return platform != "windows" && isTerminal() && term != "" && term != "dumb"
}

func copyTicketWithTerminal(parent context.Context, out io.Writer, ticket grant.Ticket, lookup clipboardLookup, hasTerminal func() bool) (string, error) {
	var b strings.Builder
	if err := writeTicketText(&b, ticket); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd, err := lookup(ctx, true)
	if err == nil {
		cmd.Stdin = strings.NewReader(b.String())
		if err = cmd.Run(); err == nil {
			return "已复制到系统剪贴板。", nil
		}
	}
	if hasTerminal() {
		if _, err = fmt.Fprintf(out, "\x1b]52;c;%s\x07", base64.StdEncoding.EncodeToString([]byte(b.String()))); err == nil {
			return "已向终端发送复制请求，是否写入取决于终端的剪贴板设置。", nil
		}
	}
	return "", fmt.Errorf("无法复制凭证 · %w", err)
}

// Clipboard import only happens on request. Treat its contents as data.
func ticketInput(ctx context.Context, s string) (string, error) {
	return ticketInputUsing(ctx, s, nativeReadClipboard, clipboardCommand)
}

func ticketInputUsing(ctx context.Context, s string, native func() (string, bool, error), lookup clipboardLookup) (string, error) {
	if !clipboardChoice(s) {
		return s, nil
	}
	if text, handled, err := native(); handled {
		if err != nil {
			if errors.Is(err, oversizePaste) {
				return "", oversizePaste
			}
			return "", errors.New("无法读取系统剪贴板，请直接粘贴整段文本并回车")
		}
		value, err := pastedValue(text)
		if err == nil && !isTicketText(value) {
			return "", errors.New("剪贴板里没有完整的 PeerTTY 邀请或回执")
		}
		return value, err
	}
	return ticketInputWith(ctx, s, lookup)
}

func ticketInputWith(ctx context.Context, s string, lookup clipboardLookup) (string, error) {
	if !clipboardChoice(s) {
		return s, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd, err := lookup(ctx, false)
	if err != nil {
		return "", fmt.Errorf("%w，请直接粘贴凭证或输入文件路径", err)
	}
	r, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(r, maxPaste+1))
	if err != nil || len(data) > maxPaste {
		cancel()
	}
	waitErr := cmd.Wait()
	if len(data) > maxPaste {
		return "", oversizePaste
	}
	if err != nil || waitErr != nil {
		return "", errors.New("无法读取系统剪贴板，请直接粘贴整段文本并回车")
	}
	value, err := pastedValue(string(data))
	if err == nil && !isTicketText(value) {
		return "", errors.New("剪贴板里没有完整的 PeerTTY 邀请或回执")
	}
	return value, err
}
