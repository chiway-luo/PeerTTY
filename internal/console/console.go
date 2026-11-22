// Package console implements the interactive device menu. Native OpenSSH owns
// the actual terminal, including authentication, interrupts and window sizing.
package console

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/transport"
)

type Settings struct {
	StateDir, KeyPath, STUN, SSHConfig string
	Version                            string
	SSHPort                            int
	TTL                                time.Duration
	NoClipboard                        bool
	// Explicit* marks flags supplied on the command line so saved settings.json
	// defaults do not override them.
	ExplicitSTUN, ExplicitSSHPort, ExplicitTTL, ExplicitNoClipboard bool
}

type Console struct {
	Settings
	in              *os.File
	out             io.Writer
	key             ed25519.PrivateKey
	fingerprint     string
	pending         chan line
	pasteTTY        *os.File
	interactive     bool
	fullScreen      bool
	autoCopy        bool
	copyToClipboard func(context.Context, io.Writer, grant.Ticket) (string, error)
	section         string
	headingDrawn    bool
	activity        string
	frame           int
}

var errBack = errors.New("返回菜单")

func Run(ctx context.Context, opts Settings, in *os.File, out io.Writer) error {
	if opts.SSHPort < 1 || opts.SSHPort > 65535 || opts.TTL <= 0 || opts.TTL > grant.MaxTTL {
		return errors.New("SSH 端口或授权时长无效")
	}
	if _, err := transport.STUNServers(opts.STUN); err != nil {
		return err
	}
	if opts.KeyPath == "" {
		if opts.StateDir == "" {
			base, err := os.UserConfigDir()
			if err != nil {
				return err
			}
			opts.StateDir = filepath.Join(base, "PeerTTY")
		}
		if err := os.MkdirAll(opts.StateDir, 0700); err != nil {
			return err
		}
		opts.KeyPath = filepath.Join(opts.StateDir, "device.key")
		if _, err := os.Stat(opts.KeyPath); errors.Is(err, os.ErrNotExist) {
			if _, err = grant.NewIdentity(opts.KeyPath); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
		}
	}
	path, err := filepath.Abs(opts.KeyPath)
	if err != nil {
		return err
	}
	opts.KeyPath = path
	applySavedSettings(&opts)
	if opts.SSHConfig != "" && opts.SSHConfig != "none" {
		opts.SSHConfig, err = userPath(opts.SSHConfig)
		if err != nil {
			return err
		}
	}
	key, err := grant.LoadIdentity(path)
	if err != nil {
		return err
	}
	t := &Console{Settings: opts, in: in, out: out, key: key, fingerprint: grant.Fingerprint(key.Public().(ed25519.PublicKey))}
	t.pasteTTY = pasteTerminal(in, out)
	t.interactive = terminalFile(in) && terminalFile(out)
	t.autoCopy = t.interactive && !opts.NoClipboard
	err = t.menu(ctx)
	if errors.Is(err, errNewWindow) {
		fmt.Fprintln(out, "已打开管理员窗口。请在新窗口选择“允许被控制”。")
		return nil
	}
	return err
}

func (t *Console) menu(ctx context.Context) error {
	closeScreen := t.openScreen()
	defer closeScreen()
	defer t.finishEntry()
	page := homePage
	var reconnectID string
	for ctx.Err() == nil {
		choice, err := t.menuChoice(ctx, page)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		page = resultPage
		command, title := menuCommand(choice)
		selectedReconnect := reconnectID
		reconnectID = ""
		t.section = title
		switch command {
		case "/quit":
			return nil
		case "/connect":
			if s, e := active.Status(ctx, t.KeyPath); e == nil && s.Role == "control" {
				err = t.waitControl(ctx, s, false)
			} else {
				err = t.control(ctx, "")
			}
		case "/link":
			var s active.State
			if s, err = active.Status(ctx, t.KeyPath); err == nil {
				err = t.linkSSH(ctx, s)
			}
			if err == nil && t.terminalUI() {
				page = homePage
			}
		case "/receipt":
			var s active.State
			if s, err = active.Status(ctx, t.KeyPath); err == nil {
				if s.Role == "control" {
					err = t.controlPanel(ctx, s, false, true)
				} else {
					err = errors.New("请在本次授权的控制端查看回执")
				}
			}
		case "/status":
			page = statusPage
		case "/revoke":
			if selectedReconnect == "" {
				err = EndGrant(ctx, t.KeyPath, t.pageOut())
			} else {
				err = active.Revoke(ctx, t.KeyPath, selectedReconnect)
				if err == nil {
					t.line("本次授权已撤销。")
				}
			}
		case "/host":
			err = t.host(ctx)
		case "/settings":
			err = t.settings(ctx)
		case "/doctor":
			err = NetworkCheck(ctx, t.pageOut(), t.STUN, false)
		case "/check":
			err = t.hostReady(ctx)
		case "/help":
			page = helpPage
		case "/clipboard":
			t.autoCopy = !t.autoCopy
			t.NoClipboard = !t.autoCopy
			_ = saveSettings(t.Settings)
			if t.autoCopy {
				t.notice("32", "✓", "凭证自动复制已开启。")
			} else {
				t.notice("32", "✓", "凭证自动复制已关闭。")
			}
		case "", "b", "/back":
			if t.terminalUI() {
				page = homePage
			}
			continue
		default:
			if isTicketText(choice) || clipboardChoice(command) {
				t.section = connectAction.title
				err = t.control(ctx, command)
			} else {
				t.section = "命令"
				t.notice("33", "!", "输入 /help 查看命令，或直接粘贴邀请。")
				continue
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, errNewWindow) {
			return err
		}
		var reconnect reconnectingGrant
		if errors.As(err, &reconnect) {
			reconnectID = reconnect.id
			page = statusPage
			continue
		}
		if errors.Is(err, errBack) {
			if t.terminalUI() {
				page = homePage
			}
			continue
		}
		if err != nil && ctx.Err() == nil {
			t.clearPage()
			t.notice("31", "!", "操作结束 · "+err.Error())
			if errors.Is(err, grant.ErrInUse) {
				fmt.Fprintln(t.out, "输入 /status 查看本机授权，/host 返回被控面板。旧版会话可在原被控窗口输入 q 撤销。")
			}
		}
	}
	return ctx.Err()
}

func (t *Console) settings(ctx context.Context) error {
	if t.terminalUI() {
		v := t.view()
		t.line(v.muted("生效范围  ") + "保存为默认设置")
		t.line(v.muted("设备密钥  ") + t.KeyPath)
	} else {
		fmt.Fprintf(t.out, "连接设置（保存为默认设置）\n设备密钥  %s\n", t.KeyPath)
	}
	urls, _ := transport.STUNServers(t.STUN)
	v, err := t.prompt(ctx, fmt.Sprintf("STUN [%s]\n回车保留，auto 使用默认服务，none 关闭，多个地址用英文逗号分隔 > ", serverList(urls)))
	if err != nil {
		return err
	}
	newSTUN := t.STUN
	switch v {
	case "-":
		newSTUN = ""
	case "":
	default:
		newSTUN = v
	}
	if _, err := transport.STUNServers(newSTUN); err != nil {
		return err
	}
	port, err := t.selectSSHPort(ctx)
	if err != nil {
		return err
	}
	t.STUN, t.SSHPort = newSTUN, port
	_ = saveSettings(t.Settings)
	t.notice("32", "✓", "连接设置已应用。")
	return nil
}

func (t *Console) selectSSHPort(ctx context.Context) (int, error) {
	for {
		v, err := t.prompt(ctx, fmt.Sprintf("本机 SSH 端口 [%d] > ", t.SSHPort))
		if err != nil || v == "" {
			return t.SSHPort, err
		}
		port, err := strconv.Atoi(v)
		if err == nil && port >= 1 && port <= 65535 {
			return port, nil
		}
		t.notice("33", "!", "请输入 1–65535 的端口，或输入 q 返回。")
	}
}

func userPath(s string) (string, error) {
	if len(s) > 1 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == 39 && s[len(s)-1] == 39)) {
		s = s[1 : len(s)-1]
	}
	if strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		s = filepath.Join(home, s[2:])
	}
	return filepath.Abs(s)
}
