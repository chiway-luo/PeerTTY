//go:build darwin || linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestStatusCountdownPreservesNativeTerminalEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("interactive terminal subprocess")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python standard library pty unavailable")
	}
	key := filepath.Join(t.TempDir(), "profile")
	fg, err := active.ReserveForeground(key, "host")
	if err != nil {
		t.Fatal(err)
	}
	defer fg.Close()
	lifetime, end, err := grant.WithLifetime(t.Context(), time.Now().Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	if err := fg.Publish(lifetime, end); err != nil {
		t.Fatal(err)
	}
	fg.Progress("ready", "fixture", "udp")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(t.Context(), 15*time.Second)
	defer stop()
	cmd := exec.CommandContext(ctx, python, "-c", statusTerminalScript, exe, key)
	cmd.Env = append(os.Environ(), "PEERTTY_TEST_PROXY=1", "TERM=xterm", "NO_COLOR=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("status page in native PTY: %v\n%s", err, out)
	}
}

// The kernel echoes partial lines in canonical mode. Drive the actual menu
// through a PTY so a screen erase cannot be mistaken for preserved input.
const statusTerminalScript = `
import fcntl, os, pty, select, struct, subprocess, sys, termios, time

master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
pending = bytearray()

def until(marker):
    end = time.monotonic() + 5
    while marker not in pending:
        left = end - time.monotonic()
        if left <= 0 or not select.select([master], [], [], left)[0]:
            raise RuntimeError("missing terminal output " + repr(marker))
        pending.extend(os.read(master, 8192))
    pos = pending.index(marker) + len(marker)
    data = bytes(pending[:pos])
    del pending[:pos]
    return data

proc = subprocess.Popen([sys.argv[1], "menu", "-key", sys.argv[2], "-no-clipboard", "-stun", "none"],
                        stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
try:
    prompt = "❯ ".encode()
    until(prompt)
    os.write(master, b"/status\n")
    until("输入下一条命令".encode())
    until(prompt)
    os.write(master, b"/hel")
    until(b"/hel")
    for _ in range(2):
        frame = until("剩余 ".encode())
        if b"\x1b[2J" in frame:
            raise AssertionError("countdown erased native input echo")
    os.write(master, b"p\n")
    until("切换自动复制".encode())
    os.write(master, b"0\n")
    if proc.wait(timeout=4):
        raise RuntimeError("menu returned an error")
finally:
    if proc.poll() is None:
        proc.kill()
        proc.wait()
    os.close(master)
`
