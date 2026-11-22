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
	"peertty/internal/grant"
	"peertty/internal/localssh"
	"peertty/internal/transport"
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

const reconnectNotice = "直连暂时中断，正在重连…"
const reconnectRevokeHint = "如需立即结束授权，可在另一个终端运行 peertty revoke（使用相同的设备身份）。"

type reconnectingGrant struct{ id string }

func (reconnectingGrant) Error() string { return reconnectNotice }

var phaseNames = map[string]string{"gathering": "收集地址", "waiting": "等待被控方批准", "connecting": "建立直连", "ready": "已连接", "disconnected": "正在重连", "offline": "直连已中断"}

func printStatus(out io.Writer, s active.State) {
	fmt.Fprintf(out, "%s · %s · %d 个终端 · %s 到期（剩余 %s）\n", roleNames[s.Role], phaseNames[s.Phase], s.Terminals, s.Deadline.Local().Format("01-02 15:04"), max(time.Duration(0), time.Until(s.Deadline)).Round(time.Second))
	showDeviceName(out, "对端", s.Device)
	if s.Note != "" {
		fmt.Fprintln(out, s.Note)
	}
}

func DisplayStatus(ctx context.Context, key string, out io.Writer) error {
	s, err := active.Status(ctx, key)
	if errors.Is(err, active.ErrInactive) {
		fmt.Fprintln(out, active.ErrInactive)
		return nil
	}
	if err != nil {
		return err
	}
	printStatus(out, s)
	return nil
}

func EndGrant(ctx context.Context, key string, out io.Writer) error {
	s, err := active.Status(ctx, key)
	if err != nil {
		return err
	}
	if err = active.Revoke(ctx, key, s.ID); err != nil {
		return err
	}
	fmt.Fprintln(out, "本次授权已撤销。")
	return nil
}

func (t *Console) waitControl(ctx context.Context, s active.State, text bool) error {
	published := false
	lastPhase := ""
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		if s.Phase != lastPhase {
			lastPhase = s.Phase
			t.clearPage()
			switch s.Phase {
			case "gathering":
				t.line("正在收集直连地址…")
			case "connecting":
				t.line("正在建立直连…")
			case "disconnected":
				return reconnectingGrant{id: s.ID}
			}
		}
		if s.Exchange != "" && !published && s.Phase == "waiting" {
			answer, err := grant.Read(s.Exchange)
			if err != nil {
				return err
			}
			t.line("回执中的直连地址 ·", transport.CountCandidates(answer.Claims.SDP))
			fileLine := fmt.Sprintf("回执文件  %s\n", s.Exchange)
			if !t.fullScreen {
				fmt.Fprint(t.out, fileLine)
			}
			if err = shareTicket(ctx, t.out, "回执", answer, t.autoCopy, text && !t.autoCopy); err != nil {
				return err
			}
			if t.fullScreen {
				// A printed receipt can be taller than the alternate screen.
				fmt.Fprint(t.out, fileLine)
			}
			fmt.Fprintln(t.out, "将回执发给被控方。批准后会打开 SSH 终端；其他窗口可运行 peertty link。")
			published = true
		}
		switch s.Phase {
		case "ready":
			t.notice("32", "●", "控制会话已连接 · "+s.Route)
			if err := t.linkSSH(ctx, s); err != nil {
				return fmt.Errorf("SSH 连接结束: %w", err)
			}
			if t.fullScreen {
				return errBack
			}
			fmt.Fprintln(t.out, "控制会话已结束。授权期内可再次输入 /link。")
			return nil
		case "offline":
			return errors.New(s.Note)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		fresh, err := active.Status(ctx, t.KeyPath)
		if err != nil {
			return err
		}
		if fresh.ID != s.ID {
			return errors.New("本次授权已结束")
		}
		s = fresh
	}
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
	args := []string{tty, "-o", "ControlPath=none", "-o", "ControlMaster=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
		"-o", "PermitLocalCommand=no", "-o", "ProxyUseFdpass=no", "-o", "HostKeyAlias=" + s.Alias, "-o", proxyCommand(exe, runtime.GOOS, proxy)}
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
	return linkSSH(ctx, key, s, in, out, diag, command, (*exec.Cmd).Run)
}

func (t *Console) linkSSH(ctx context.Context, s active.State) error {
	if s.Role == "control" && s.Phase == "disconnected" {
		return reconnectingGrant{id: s.ID}
	}
	return linkSSH(ctx, t.KeyPath, s, t.in, t.out, t.out, RemoteCommand{}, func(cmd *exec.Cmd) error {
		return t.nativeSSH(cmd.Run)
	})
}

// Wait only on the grant explicitly selected by the caller, never a newly paired grant.
func waitReconnect(ctx context.Context, s active.State, diag io.Writer, tick <-chan time.Time, status func(context.Context) (active.State, error)) (active.State, error) {
	ctx, cancel := context.WithDeadline(ctx, s.Deadline)
	defer cancel()
	fmt.Fprintln(diag, reconnectNotice)
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
			continue
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
		if ctx.Err() != nil || errors.Is(err, active.ErrInactive) || err == nil && s.ID != id {
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

func linkSSH(ctx context.Context, key string, s active.State, in *os.File, out, diag io.Writer, command RemoteCommand, run func(*exec.Cmd) error) (result error) {
	status := func(ctx context.Context) (active.State, error) { return active.Status(ctx, key) }
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
	if len(command.Args) == 0 && terminalFile(diag) {
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
