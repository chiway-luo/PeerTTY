package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"peertty/internal/active"
	"runtime"
	"strings"
	"time"
	"unicode"

	"peertty/internal/bridge"
	"peertty/internal/filelock"
	"peertty/internal/grant"
	"peertty/internal/localssh"
	"peertty/internal/session"
	"peertty/internal/transport"
)

const proxyEnv = "PEERTTY_CONSOLE_PROXY"
const programEnv = "PEERTTY_CONSOLE_PROGRAM"

type handoff struct {
	Key, Peer, Offer, Answer, STUN string
	Text, Copy                     bool
}

// RunProxy is OpenSSH's child. It owns the role lease until its stream closes.
func RunProxy(ctx context.Context, end bridge.Endpoint, log io.Writer) error {
	var h handoff
	if err := json.Unmarshal([]byte(os.Getenv(proxyEnv)), &h); err != nil {
		return errors.New("请从 PeerTTY 终端菜单发起连接")
	}
	if !filepath.IsAbs(h.Key) || !filepath.IsAbs(h.Offer) || !filepath.IsAbs(h.Answer) || !grant.ValidFingerprint(h.Peer) {
		return errors.New("无效的本地连接参数")
	}
	worker, err := filelock.Try(h.workerPath())
	if err != nil {
		return err
	}
	defer worker.Close()
	if busy, err := held(h.Offer); err != nil || !busy {
		return errors.New("发起连接的终端已关闭")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	connected := make(chan struct{})
	go h.watchMenu(ctx, cancel, connected)
	lease, err := grant.LeaseIdentity(h.Key)
	if err != nil {
		return err
	}
	defer lease.Close()
	key, err := grant.LoadIdentity(h.Key)
	if err != nil {
		return err
	}
	offer, err := grant.Read(h.Offer)
	if err != nil {
		return err
	}
	return session.RunControl(ctx, session.Config{Key: key, Peer: h.Peer, STUN: h.STUN}, offer, end, func(answer grant.Ticket) error {
		if err := answer.WriteNew(h.Answer); err != nil {
			return err
		}
		fmt.Fprintln(log, "回执中的直连地址 ·", transport.CountCandidates(answer.Claims.SDP))
		fmt.Fprintf(log, "回执文件  %s\n", h.Answer)
		if err := shareTicket(ctx, log, "回执", answer, h.Copy, h.Text && !h.Copy); err != nil {
			return err
		}
		fmt.Fprintln(log, "请发回回执，等待被控方批准。")
		return nil
	}, func(route string) { close(connected); fmt.Fprintf(log, "控制会话已连接 · %s\n", route) })
}
func proxyCommand(exe, platform, command string) string {
	if platform == "windows" {
		// Windows filenames cannot contain quotes. OpenSSH expands percent tokens.
		return `ProxyCommand="` + strings.ReplaceAll(exe, "%", "%%") + `" ` + command
	}
	// Expansion by the shell happens inside double quotes; no path becomes shell syntax.
	return `ProxyCommand="$PEERTTY_CONSOLE_PROGRAM" ` + command
}

func (t *Console) control(ctx context.Context, invitation string) (result error) {
	if !t.fullScreen {
		fmt.Fprintln(t.out, "控制设备 · 输入 q 返回")
	}
	if err := t.checkSSH(ctx, false, localssh.CheckClient); err != nil {
		return err
	}
	var err error
	if invitation == "" {
		if runtime.GOOS == "darwin" {
			t.line("按 ⌘V 粘贴邀请并回车，或输入 p 从剪贴板读取。")
		}
		invitation, err = t.prompt(ctx, "邀请文件路径或整段邀请文本 > ")
		if err != nil {
			return err
		}
	}
	invitation, err = ticketInput(ctx, invitation)
	if err != nil {
		return err
	}
	if isTicketText(invitation) {
		t.line("已收到邀请文本。")
	}
	offer, err := readTicket(invitation)
	if err != nil {
		return err
	}
	peer := grant.Fingerprint(offer.Claims.Issuer)
	if peer == t.fingerprint {
		return errors.New("这份邀请来自本机，请粘贴对方发来的邀请")
	}
	if err = offer.VerifyOffer(peer, t.fingerprint, time.Now()); err != nil {
		return fmt.Errorf("邀请校验失败，请对方重新发送本次邀请 · %w", err)
	}
	t.notice("32", "✓", fmt.Sprintf("邀请签名已核验，有效至 %s。", offer.Deadline().Local().Format("15:04:05")))
	showDeviceName(t.out, "被控设备", offer.Claims.DeviceName)
	suggested := offer.Claims.SSHUser
	if len(offer.Claims.SSHHostKey) > 0 && validSSHUser(suggested) {
		fmt.Fprintf(t.out, "回车使用本次授权登录 %s，输入 /ssh 可改用已有的 SSH 凭据。\n", suggested)
	} else if validSSHUser(suggested) {
		fmt.Fprintf(t.out, "邀请中的登录账号  %s（回车使用，也可输入其他账号）\n", suggested)
	} else {
		suggested = ""
	}
	user, err := t.prompt(ctx, "远端 SSH 用户名 > ")
	if err != nil {
		return err
	}
	standard := user == "/ssh"
	if standard {
		user, err = t.prompt(ctx, "远端 SSH 账号 [回车使用邀请中的账号] > ")
		if err != nil {
			return err
		}
	}
	if user == "" {
		user = suggested
	}
	if !validSSHUser(user) {
		return errors.New("请输入有效的 SSH 用户名")
	}
	scoped := !standard && len(offer.Claims.SSHHostKey) > 0 && user == suggested
	var identity string
	if !scoped {
		identity, err = t.prompt(ctx, "SSH 登录私钥路径 [回车使用系统 SSH 默认认证] > ")
		if err != nil {
			return err
		}
	}
	if identity != "" {
		identity, err = userPath(identity)
		if err != nil {
			return err
		}
		info, err := os.Stat(identity)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("登录私钥应为普通文件")
		}
	}
	if offer.Reusable() {
		st, err := active.Start(ctx, active.Options{Role: "control", Key: t.KeyPath, STUN: t.STUN, User: user, Identity: identity, SSHConfig: t.SSHConfig, Offer: offer, Scoped: scoped})
		if err != nil {
			return err
		}
		return t.waitControl(ctx, st, isTicketText(invitation))
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "peertty-control-*")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(dir)) }()
	h := handoff{Key: t.KeyPath, Peer: peer, Offer: filepath.Join(dir, "received.offer"), Answer: filepath.Join(dir, "session.answer"), STUN: t.STUN, Text: isTicketText(invitation), Copy: t.autoCopy}
	if err = offer.WriteNew(h.Offer); err != nil {
		return err
	}
	alias := "peertty-" + strings.TrimPrefix(peer, "sha256:")
	args := sshArgs(exe, "_menu-proxy", active.State{Alias: alias, Identity: identity, User: user, SSHConfig: t.SSHConfig}, RemoteCommand{})
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	ssh, err := localssh.ClientPath()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, ssh, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = t.in, t.out, t.out
	cmd.Env = append(os.Environ(), programEnv+"="+exe, proxyEnv+"="+string(data))
	restore, err := keepSSHInput(t.in)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, restore()) }()
	t.line("回执生成后发给被控方。对方批准后进入 SSH 终端，输入 exit 返回菜单。")
	if err = t.nativeSSH(func() error { return h.runSSH(cmd) }); err != nil {
		return fmt.Errorf("SSH 连接结束: %w", err)
	}
	if t.fullScreen {
		return errBack
	}
	fmt.Fprintln(t.out, "控制会话已结束。")
	return nil
}

func validSSHUser(name string) bool {
	return name != "" && len(name) <= 256 && !strings.HasPrefix(name, "-") &&
		!strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) || unicode.IsSpace(r) })
}
