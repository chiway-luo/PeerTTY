package console

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"peertty/internal/grant"
)

func clipboardChoice(s string) bool {
	return strings.EqualFold(s, "p") || s == "/paste"
}

func shareTicket(ctx context.Context, out io.Writer, kind string, ticket grant.Ticket, copyOn, show bool) error {
	if copyOn {
		status, err := copyTicket(ctx, out, ticket)
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
	switch runtime.GOOS {
	case "darwin":
		if write {
			return exec.CommandContext(ctx, "/usr/bin/pbcopy"), nil
		}
		return exec.CommandContext(ctx, "/usr/bin/pbpaste", "-Prefer", "txt"), nil
	case "windows":
		exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		script := "[Console]::Write((Get-Clipboard -Raw -ErrorAction Stop))"
		if write {
			script = "Set-Clipboard -Value ([Console]::In.ReadToEnd()) -ErrorAction Stop"
		}
		return exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-STA", "-Command", script), nil
	case "linux":
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			name := "wl-paste"
			args := []string{"--no-newline"}
			if write {
				name, args = "wl-copy", nil
			}
			if exe, err := exec.LookPath(name); err == nil {
				return exec.CommandContext(ctx, exe, args...), nil
			}
		}
		if os.Getenv("DISPLAY") != "" {
			if exe, err := exec.LookPath("xclip"); err == nil {
				mode := "-out"
				if write {
					mode = "-in"
				}
				return exec.CommandContext(ctx, exe, "-selection", "clipboard", mode), nil
			}
			if exe, err := exec.LookPath("xsel"); err == nil {
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
func copyTicket(parent context.Context, out io.Writer, ticket grant.Ticket) (string, error) {
	var b strings.Builder
	if err := writeTicketText(&b, ticket); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd, err := clipboardCommand(ctx, true)
	if err == nil {
		cmd.Stdin = strings.NewReader(b.String())
		if err = cmd.Run(); err == nil {
			return "已复制到系统剪贴板。", nil
		}
	}
	if runtime.GOOS != "windows" && terminalFile(out) && os.Getenv("TERM") != "" && os.Getenv("TERM") != "dumb" {
		if _, err = fmt.Fprintf(out, "\x1b]52;c;%s\x07", base64.StdEncoding.EncodeToString([]byte(b.String()))); err == nil {
			return "已向终端发送复制请求，是否写入取决于终端的剪贴板设置。", nil
		}
	}
	return "", fmt.Errorf("无法复制凭证 · %w", err)
}

// Clipboard import only happens on request. Treat its contents as data.
func ticketInput(ctx context.Context, s string) (string, error) {
	if !clipboardChoice(s) {
		return s, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd, err := clipboardCommand(ctx, false)
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
