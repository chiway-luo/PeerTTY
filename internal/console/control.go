package console

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"peertty/internal/active"
	"peertty/internal/bridge"
	"peertty/internal/filelock"
	"peertty/internal/grant"
	"peertty/internal/localssh"
	"peertty/internal/session"
)

const proxyEnv = "PEERTTY_CONSOLE_PROXY"
const programEnv = "PEERTTY_CONSOLE_PROGRAM"

type handoff struct {
	Key, Peer, Offer, Answer, STUN string
	Text, Copy, Interactive        bool
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
	foreground, err := active.ReserveForeground(h.Key, "control")
	if err != nil {
		return err
	}
	defer foreground.Close()
	offer, err := grant.Read(h.Offer)
	if err != nil {
		return err
	}
	codePath := h.Offer + ".pair"
	code, err := grant.ReadPairingCode(codePath)
	if err != nil {
		return err
	}
	if err = os.Remove(codePath); err != nil {
		return err
	}
	var key ed25519.PrivateKey
	if offer.Pinned() {
		key, err = grant.LoadIdentity(h.Key)
		if err != nil {
			return err
		}
	}
	panel := &Console{out: log, autoCopy: h.Copy, section: "控制端回执"}
	if h.Interactive && terminalFile(log) {
		if keyboard, err := os.Open(terminalInputPath); err == nil {
			defer keyboard.Close()
			panel.in, panel.interactive = keyboard, true
		}
	}
	st := active.State{Role: "control", Phase: "gathering", Deadline: offer.Deadline(), Exchange: h.Answer}
	cfg := session.Config{Key: key, Peer: h.Peer, STUN: h.STUN, Profile: h.Key, PairingCode: code, Foreground: foreground}
	return panel.singleUseReceipt(ctx, st, h.Text, func(ctx context.Context, publish func(grant.Ticket) error, ready func(string)) error {
		return session.RunControl(ctx, cfg, offer, end, publish, func(route string) {
			close(connected)
			ready(route)
		})
	})
}
func proxyCommand(exe, platform, command string) string {
	if platform == "windows" {
		// Windows filenames cannot contain quotes. OpenSSH expands percent tokens.
		return `ProxyCommand="` + strings.ReplaceAll(exe, "%", "%%") + `" ` + command
	}
	// Expansion by the shell happens inside double quotes; no path becomes shell syntax.
	return `ProxyCommand="$PEERTTY_CONSOLE_PROGRAM" ` + command
}

type controllerServices struct {
	check  func() localssh.Check
	status func(context.Context, string) (active.State, error)
	start  func(context.Context, active.Options) (active.State, error)
}

func (t *Console) control(ctx context.Context, invitation string) error {
	return t.controlWith(ctx, invitation, controllerServices{localssh.CheckClient, active.Status, active.Start})
}

func (t *Console) controlWith(ctx context.Context, invitation string, services controllerServices) (result error) {
	if !t.terminalUI() {
		fmt.Fprintln(t.out, "控制设备 · 输入 q 返回")
	}
	if err := t.checkSSH(ctx, false, services.check); err != nil {
		return err
	}
	var err error
	if invitation == "" {
		t.line("粘贴邀请并回车，或输入 p 从剪贴板读取。")
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
	peer := offer.Sender()
	if offer.Pinned() {
		var profile ed25519.PrivateKey
		profile, err = grant.LoadIdentity(t.KeyPath)
		if err == nil {
			err = offer.VerifyOffer(peer, grant.Fingerprint(profile.Public().(ed25519.PublicKey)), time.Now())
		}
	} else {
		err = offer.VerifyOpenOffer(time.Now())
	}
	if err != nil {
		return fmt.Errorf("邀请校验失败，请对方重新发送本次邀请 · %w", err)
	}
	if st, statusErr := services.status(ctx, t.KeyPath); statusErr == nil {
		if st.OneShot {
			return active.ErrOneShot
		}
		if st.Role == "control" && st.Exchange != "" {
			answer, err := grant.Read(st.Exchange)
			if err != nil {
				return err
			}
			if answer.VerifyAnswer(offer, time.Now()) == nil {
				return t.controlPanel(ctx, st, isTicketText(invitation), st.Phase != "waiting")
			}
		}
		return grant.ErrInUse
	} else if !errors.Is(statusErr, active.ErrInactive) {
		return statusErr
	}
	code, err := t.askPairingCode(ctx, offer)
	if err != nil {
		return err
	}
	t.notice("32", "✓", fmt.Sprintf("邀请签名已核验，有效至 %s。", offer.Deadline().Local().Format("15:04:05")))
	showSessionIdentity(t.out, "被控设备", offer.Claims.Issuer, offer.Claims.DeviceName)
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
		st, err := services.start(ctx, active.Options{Role: "control", Key: t.KeyPath, STUN: t.STUN, User: user, Identity: identity, SSHConfig: t.SSHConfig, Offer: offer, Scoped: scoped, PairingCode: code})
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
	h := handoff{Key: t.KeyPath, Peer: peer, Offer: filepath.Join(dir, "received.offer"), Answer: filepath.Join(dir, "session.answer"), STUN: t.STUN, Text: isTicketText(invitation), Copy: t.autoCopy, Interactive: t.interactive}
	if err = offer.WriteNew(h.Offer); err != nil {
		return err
	}
	if err = os.WriteFile(h.Offer+".pair", []byte(code), 0600); err != nil {
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
	if t.terminalUI() {
		return errBack
	}
	fmt.Fprintln(t.out, "控制会话已结束。")
	return nil
}

func (t *Console) askPairingCode(ctx context.Context, offer grant.Ticket) (grant.PairingCode, error) {
	entry, stop := context.WithDeadline(ctx, offer.Deadline())
	defer stop()
	for {
		input, err := t.prompt(entry, "输入被控方通过可信渠道单独提供的一次性配对码 > ")
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if entry.Err() != nil || !time.Now().Before(offer.Deadline()) {
			return "", errors.New("邀请已到期，请被控方重新发起授权")
		}
		if err != nil {
			return "", err
		}
		code, err := grant.ParsePairingCode(input)
		if err == nil {
			err = code.VerifyProof(offer)
		}
		if err == nil {
			return code, nil
		}
		t.notice("33", "!", err.Error()+"。请重新输入配对码，或输入 q 返回。")
	}
}

func validSSHUser(name string) bool {
	return name != "" && len(name) <= 256 && !strings.HasPrefix(name, "-") &&
		!strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) || unicode.IsSpace(r) })
}
