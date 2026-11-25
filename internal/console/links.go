package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"peertty/internal/active"
	"peertty/internal/localssh"
)

func IdentityPath(stateDir, key string) (string, error) {
	if stateDir != "" && key != "" {
		return "", errors.New("-state-dir 和 -key 请选择一个")
	}
	if key == "" {
		if stateDir == "" {
			d, err := os.UserConfigDir()
			if err != nil {
				return "", err
			}
			stateDir = filepath.Join(d, "PeerTTY")
		}
		key = filepath.Join(stateDir, "device.key")
	}
	return filepath.Abs(key)
}

var roleNames = map[string]string{"host": "被控端", "control": "控制端"}

const sshLoginNotice = "直连已建立，正在登录 SSH…"

const reconnectNotice = "网络连接已断开，正在重连…"
const reconnectRevokeHint = "如需立即结束授权，可在另一个终端运行 peertty revoke（使用相同的设备身份）。"

type reconnectingGrant struct{ id string }

func (reconnectingGrant) Error() string { return reconnectNotice }

var phaseNames = map[string]string{"gathering": "收集地址", "waiting": "等待被控方批准", "connecting": "建立直连", "ready": "已连接", "disconnected": "正在重连", "offline": "直连已中断"}

func phaseName(s active.State) string {
	if s.Role == "host" && s.Phase == "waiting" {
		return "等待回执"
	}
	return phaseNames[s.Phase]
}

func printStatus(out io.Writer, s active.State) {
	fmt.Fprintf(out, "%s · %s · %d 个终端 · %s 到期（剩余 %s）\n", roleNames[s.Role], phaseName(s), s.Terminals, s.Deadline.Local().Format("01-02 15:04"), s.TimeLeft().Round(time.Second))
	showDeviceName(out, "对端", s.Device)
	if s.Route != "" {
		fmt.Fprintln(out, "直连路径  "+s.Route)
	}
	if s.Note != "" {
		fmt.Fprintln(out, s.Note)
	}
}

func DisplayStatus(ctx context.Context, key string, out io.Writer) error {
	return displayStatusWith(ctx, key, out, active.Status)
}

func displayStatusWith(ctx context.Context, key string, out io.Writer, status func(context.Context, string) (active.State, error)) error {
	s, err := status(ctx, key)
	if errors.Is(err, active.ErrInactive) {
		fmt.Fprintln(out, active.ErrInactive)
		if reason, at, ok := active.LastError(key); ok {
			fmt.Fprintf(out, "上次授权异常结束（%s）· %s\n", at.Local().Format("15:04:05"), reason)
			if logPath := active.LogPath(key); logPath != "" {
				fmt.Fprintf(out, "诊断日志  %s\n", logPath)
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	printStatus(out, s)
	return nil
}

func EndGrant(ctx context.Context, key string, out io.Writer) error {
	return endGrantWith(ctx, key, out, active.Status, active.Revoke)
}

func endGrantWith(ctx context.Context, key string, out io.Writer, status func(context.Context, string) (active.State, error), revoke func(context.Context, string, string) error) error {
	s, err := status(ctx, key)
	if err != nil {
		return err
	}
	if err = revoke(ctx, key, s.ID); err != nil {
		return err
	}
	fmt.Fprintln(out, "本次授权已撤销。")
	return nil
}

// RemoteCommand selects a login shell or a single SSH command. Ordinary
// commands keep their separate stdout and stderr unless a terminal is requested.
type RemoteCommand struct {
	Args []string
	TTY  bool
}

func sshArgs(exe, proxy string, s active.State, command RemoteCommand) []string {
	tty := "-tt"
	if len(command.Args) > 0 && !command.TTY {
		tty = "-T"
	}
	args := []string{tty, "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=5", "-o", "ControlPath=none", "-o", "ControlMaster=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
		"-o", "PermitLocalCommand=no", "-o", "ProxyUseFdpass=no", "-o", "HostKeyAlias=" + s.Alias, "-o", proxyCommand(exe, runtime.GOOS, proxy)}
	if proxy == "_link-proxy" {
		// Allow the proxy's 30-second stream opening and the initial SSH handshake.
		args = append(args, "-o", "ConnectTimeout=45")
	}
	if s.KnownHosts != "" {
		known := strconv.Quote(strings.ReplaceAll(filepath.ToSlash(s.KnownHosts), "%", "%%"))
		args = append(args, "-F", "none", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey", "-o", "IdentityAgent=none",
			"-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "GlobalKnownHostsFile=none", "-o", "UserKnownHostsFile="+known)
	} else if s.SSHConfig != "" {
		args = append(args, "-F", s.SSHConfig)
	}
	if s.Identity != "" {
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", s.Identity)
	}
	args = append(args, "-l", s.User, s.Alias)
	return append(args, command.Args...)
}

func Link(ctx context.Context, key string, in *os.File, out, diag io.Writer, command RemoteCommand) error {
	s, err := active.Status(ctx, key)
	if err != nil {
		return err
	}
	return linkSSH(ctx, key, s, in, out, diag, command, func(cmd *exec.Cmd) error {
		if len(command.Args) == 0 || command.TTY {
			fmt.Fprintln(diag, sshLoginNotice)
		}
		return cmd.Run()
	})
}

func (t *Console) linkSSH(ctx context.Context, s active.State) error {
	if s.Role == "control" && s.Phase == "disconnected" {
		return reconnectingGrant{id: s.ID}
	}
	err := linkSSH(ctx, t.KeyPath, s, t.in, t.out, t.out, RemoteCommand{}, func(cmd *exec.Cmd) error {
		return t.nativeSSH(func() error {
			// Print in the native screen: the receipt view may use an alternate buffer.
			fmt.Fprintln(t.out, sshLoginNotice)
			return cmd.Run()
		})
	})
	if err != nil && ctx.Err() == nil {
		fresh, statusErr := active.Status(ctx, t.KeyPath)
		return describeLinkExit(s.ID, err, fresh, statusErr)
	}
	return err
}

// describeLinkExit pairs the original OpenSSH error with the latest local grant status.
func describeLinkExit(id string, err error, fresh active.State, statusErr error) error {
	switch {
	case errors.Is(statusErr, active.ErrInactive) || statusErr == nil && fresh.ID != id:
		return fmt.Errorf("SSH 会话已断开，本次授权已结束 · %w", err)
	case statusErr == nil && fresh.Phase == "disconnected":
		return reconnectingGrant{id: id}
	case statusErr == nil && fresh.Phase == "offline":
		return fmt.Errorf("SSH 会话已断开 · %s · %w", fresh.Note, err)
	case statusErr == nil && fresh.Phase == "ready":
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 255 {
			return fmt.Errorf("直连仍可用，但 SSH 登录未完成或终端已断开。可输入 /link 用本次授权重试；退出菜单可查看 SSH 原始提示 · %w", err)
		}
	}
	return err
}

// Wait only on the grant explicitly selected by the caller, never a newly paired grant.
func waitReconnect(ctx context.Context, s active.State, diag io.Writer, tick <-chan time.Time, status func(context.Context) (active.State, error)) (active.State, error) {
	ctx, cancel := context.WithTimeout(ctx, s.TimeLeft())
	defer cancel()
	fmt.Fprintln(diag, reconnectNotice)
	animate := terminalFile(diag)
	frame := 0
	if animate {
		defer fmt.Fprint(diag, "\r \r")
	}
	for {
		select {
		case <-ctx.Done():
			return active.State{}, ctx.Err()
		case <-tick:
		}
		fresh, err := status(ctx)
		if err != nil {
			return active.State{}, err
		}
		if ctx.Err() != nil {
			return active.State{}, ctx.Err()
		}
		if fresh.ID != s.ID || fresh.Role != "control" {
			return active.State{}, errors.New("本次授权已结束")
		}
		switch fresh.Phase {
		case "ready":
			fmt.Fprintln(diag, "直连已恢复。")
			return fresh, nil
		case "disconnected":
			if animate {
				fmt.Fprintf(diag, "%c\r", spinFrames[frame])
				frame = (frame + 1) % len(spinFrames)
			}
		default:
			return active.State{}, errors.New("直连未恢复，请重新配对")
		}
	}
}

// Observe only; never restart a live OpenSSH process or replay its input.
func watchSSHConnection(ctx context.Context, id string, diag io.Writer, tick <-chan time.Time, status func(context.Context) (active.State, error)) {
	previous := "ready"
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		s, err := status(ctx)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, active.ErrInactive) || err == nil && s.ID != id {
			fmt.Fprint(diag, "\r\nSSH 会话已断开，本次授权已结束。\r\n")
			return
		}
		if err != nil || s.Phase == previous {
			continue
		}
		switch s.Phase {
		case "disconnected":
			fmt.Fprintf(diag, "\r\n%s\r\n%s\r\n", reconnectNotice, reconnectRevokeHint)
		case "ready":
			fmt.Fprint(diag, "\r\n直连已恢复。\r\n")
		case "offline":
			fmt.Fprint(diag, "\r\n直连未恢复，请重新配对。\r\n")
			return
		}
		previous = s.Phase
	}
}

func linkSSH(ctx context.Context, key string, s active.State, in *os.File, out, diag io.Writer, command RemoteCommand, run func(*exec.Cmd) error) error {
	return linkSSHWithStatus(ctx, key, s, in, out, diag, command, run,
		func(ctx context.Context) (active.State, error) { return active.Status(ctx, key) })
}

func linkSSHWithStatus(ctx context.Context, key string, s active.State, in *os.File, out, diag io.Writer, command RemoteCommand, run func(*exec.Cmd) error, status func(context.Context) (active.State, error)) (result error) {
	if s.Role == "control" && s.Phase == "disconnected" {
		if terminalFile(diag) {
			fmt.Fprintln(diag, reconnectRevokeHint)
		}
		tick := time.NewTicker(300 * time.Millisecond)
		defer tick.Stop()
		var err error
		s, err = waitReconnect(ctx, s, diag, tick.C, status)
		if err != nil {
			return err
		}
	}
	if s.Role != "control" || s.Phase != "ready" {
		if s.Phase == "offline" {
			return fmt.Errorf("直连已断开，请重新配对 · %s", s.Note)
		}
		return errors.New("本机尚无已连接的控制授权，输入 peertty status 查看状态")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ssh, err := localssh.ClientPath()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, ssh, sshArgs(exe, "_link-proxy", s, command)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, diag
	cmd.Env = append(os.Environ(), programEnv+"="+exe, "PEERTTY_LINK_KEY="+key, "PEERTTY_LINK_ID="+s.ID)
	restore, err := keepSSHInput(in)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, restore()) }()
	// Files include redirected diagnostics and PTY hosts. All CLI entry
	// points pass one, and os.File supports writes alongside the SSH child.
	if _, ok := diag.(*os.File); ok && (len(command.Args) == 0 || command.TTY) {
		watch, stop := context.WithCancel(ctx)
		tick := time.NewTicker(time.Second)
		done := make(chan struct{})
		go func() {
			defer close(done)
			watchSSHConnection(watch, s.ID, diag, tick.C, status)
		}()
		defer func() { stop(); tick.Stop(); <-done }()
	}
	return run(cmd)
}

// OpenSSH alone interprets remote shell input. This proxy connects only to the
// authenticated worker holding the exact grant selected by the caller.
func LinkProxy(ctx context.Context, in io.Reader, out io.Writer) error {
	key, id := os.Getenv("PEERTTY_LINK_KEY"), os.Getenv("PEERTTY_LINK_ID")
	if !filepath.IsAbs(key) || id == "" {
		return errors.New("请使用 peertty link")
	}
	c, err := active.Pipe(ctx, key, id)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	go func() { _, _ = io.Copy(c, in); _ = c.CloseWrite() }()
	_, err = io.Copy(out, c)
	return err
}
