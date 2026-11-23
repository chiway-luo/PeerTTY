package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/localssh"
	"peertty/internal/transport"
)

func (t *Console) host(ctx context.Context) error {
	if current, err := active.Status(ctx, t.KeyPath); err == nil {
		if current.Role == "host" {
			return t.watchHost(ctx, current)
		}
		return grant.ErrInUse
	} else if !errors.Is(err, active.ErrInactive) {
		return err
	}
	if !t.terminalUI() {
		fmt.Fprintln(t.out, "允许被控制 · 输入 q 返回")
	}
	initial, err := t.hostReady(ctx)
	if err != nil {
		return err
	}
	ttl, err := t.askDuration(ctx, initial)
	if err != nil {
		return err
	}
	current, err := t.hostReady(ctx)
	if err != nil {
		return err
	}
	st, err := active.Start(ctx, active.Options{Role: "host", Key: t.KeyPath, Port: t.SSHPort, TTL: ttl, STUN: t.STUN, RequireScoped: current.ScopedOnly})
	if err != nil {
		return err
	}
	return t.watchHost(ctx, st)
}

const hostPrompt = "回执 / p 读取 / c 复制 / v 显示 / b 返回 / q 撤销 > "

func (t *Console) watchHost(ctx context.Context, st active.State) error {
	t.section = "被控面板"
	defer t.setActivity("")
	spin := time.NewTicker(spinInterval)
	defer spin.Stop()
	poll := time.NewTicker(600 * time.Millisecond)
	defer poll.Stop()
	var offer grant.Ticket
	var pending *grant.Ticket
	var input <-chan line
	var previous active.State
	for {
		if st.Phase != previous.Phase || ((st.Phase == "ready" || st.Phase == "disconnected" || st.Phase == "connecting") && st != previous) {
			t.setActivity(waitLabel(st))
			t.clearPage()
			switch st.Phase {
			case "gathering":
				t.line("正在收集直连地址…")
			case "waiting":
				var err error
				offer, err = grant.Read(st.Exchange)
				if err != nil {
					return err
				}
				if !t.terminalUI() {
					t.describeOffer(st, offer)
				}
				if err = t.shareTicket(ctx, "邀请", offer, t.autoCopy, !t.interactive); err != nil {
					return err
				}
				if t.terminalUI() {
					t.describeOffer(st, offer)
				}
				t.line("将邀请私发给对方，再粘贴回执或输入文件路径。")
				t.writeHostPrompt(false)
			case "connecting":
				t.line("已批准本次连接。正在进行双向 UDP 探测。")
				if st.Note != "" {
					t.line(st.Note)
				}
			case "ready":
				t.notice("32", "●", "被控会话已连接 · "+st.Route)
				if !t.terminalUI() {
					t.line("b 返回，q 撤销并关闭全部终端。")
				}
				if st.Note != "" {
					t.line(st.Note)
				}
				t.line("已连接终端 ", st.Terminals)
			case "disconnected":
				t.notice("33", "!", reconnectNotice)
				if st.Note != "" {
					t.line(st.Note)
				}
			case "offline":
				return errors.New(st.Note)
			}
			if st.Phase == "connecting" || st.Phase == "ready" || st.Phase == "disconnected" {
				t.liveHostPrompt()
			}
		}
		previous = st
		if input == nil && st.Phase != "gathering" {
			input = t.next()
		}
		pollInterval := poll.C
		if st.Phase == "gathering" {
			pollInterval = nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-spin.C:
			t.advanceActivity()
			if st.Phase != "gathering" {
				continue
			}
			fresh, err := active.Status(ctx, t.KeyPath)
			if err != nil || fresh.ID != st.ID {
				return t.handleHostEnded(ctx, st, err)
			}
			st = fresh
		case <-pollInterval:
			fresh, err := active.Status(ctx, t.KeyPath)
			if err != nil || fresh.ID != st.ID {
				return t.handleHostEnded(ctx, st, err)
			}
			st = fresh
		case item := <-input:
			t.submitEntry()
			input = nil
			if errors.Is(item.err, io.EOF) {
				return io.EOF
			}
			if item.err != nil {
				if _, ok := item.err.(inputIssue); ok {
					t.notice("33", "!", item.err.Error())
					t.hostInputPrompt(st, offer, pending)
					continue
				}
				return item.err
			}
			switch strings.ToLower(item.text) {
			case "b", "/back":
				if !t.fullScreen {
					fmt.Fprintln(t.out, "授权继续有效。输入 /status 查看状态，/revoke 撤销。")
				}
				return errBack
			case "q", "/revoke":
				if err := active.Revoke(ctx, t.KeyPath, st.ID); err != nil {
					return err
				}
				t.notice("32", "✓", "本次授权已撤销。")
				return nil
			case "v", "c":
				if st.Phase == "waiting" {
					if err := t.shareTicket(ctx, "邀请", offer, strings.EqualFold(item.text, "c"), strings.EqualFold(item.text, "v")); err != nil {
						return err
					}
				}
			default:
				if st.Phase != "waiting" {
					break
				}
				if pending != nil {
					if strings.EqualFold(item.text, "y") {
						if err := active.Approve(ctx, t.KeyPath, st.ID, *pending); err != nil {
							return err
						}
						pending = nil
						st.Phase = "connecting"
						continue
					}
					if strings.EqualFold(item.text, "r") {
						pending = nil
					}
				} else if item.text != "" {
					value, err := ticketInput(ctx, item.text)
					var answer grant.Ticket
					if err == nil {
						answer, err = readTicket(value)
					}
					if err == nil {
						err = st.CheckAnswer(offer, answer, time.Now())
					}
					if err != nil {
						t.notice("33", "!", "回执无效，可重新输入 · "+err.Error())
					} else {
						pending = &answer
					}
				}
			}
			t.hostInputPrompt(st, offer, pending)
		}
	}
}

func (t *Console) handleHostEnded(ctx context.Context, st active.State, err error) error {
	t.clearPage()
	if time.Until(st.Deadline) <= 0 {
		if err := active.WaitEnded(ctx, t.KeyPath, st.ID); err != nil {
			return err
		}
		t.line("授权已到期。")
		return nil
	}
	if err != nil && !errors.Is(err, active.ErrInactive) {
		return err
	}
	if reason, _, ok := active.LastError(t.KeyPath); ok {
		return errors.New(reason)
	}
	t.line("被控会话已结束。")
	return nil
}

func (t *Console) describeOffer(st active.State, offer grant.Ticket) {
	t.line("邀请中的直连地址 ·", transport.CountCandidates(offer.Claims.SDP))
	t.line("邀请文件 ", st.Exchange)
	t.line("有效至   ", st.Deadline.Local().Format("01-02 15:04"))
	if st.Note != "" {
		t.line("本次使用系统 SSH 认证 ·", st.Note)
	}
}

func (t *Console) liveHostPrompt() {
	if t.terminalUI() {
		v := t.view()
		fmt.Fprint(t.pageOut(), v.composer("输入面板命令", v.muted("b 返回  q 撤销并关闭全部终端")))
	}
}

func (t *Console) hostInputPrompt(st active.State, offer grant.Ticket, pending *grant.Ticket) {
	if st.Phase != "waiting" {
		if t.terminalUI() {
			fmt.Fprint(t.pageOut(), t.view().status(st, nil))
			t.liveHostPrompt()
		} else {
			printStatus(t.out, st)
		}
		return
	}
	if pending == nil {
		if t.terminalUI() {
			t.describeOffer(st, offer)
		}
		t.writeHostPrompt(false)
		return
	}
	showPeerIdentity(t.pageOut(), "请求控制的设备", t.KeyPath, pending.Claims.Issuer, pending.Claims.DeviceName)
	t.notice("32", "✓", "回执已核验。关闭菜单后，此设备仍可在授权期内打开多个终端。")
	if len(pending.Claims.SSHLoginKey) > 0 {
		fmt.Fprintf(t.out, "批准后可直接登录当前账号 %s。\n", offer.Claims.SSHUser)
	} else {
		fmt.Fprintln(t.out, "每次登录使用被控机的系统 SSH 认证。")
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		fmt.Fprintln(t.out, "登录后，对方可以按该账号已有的 sudo 规则执行管理员命令。")
	}
	t.writeHostPrompt(true)
}

func (t *Console) writeHostPrompt(approval bool) {
	if !t.terminalUI() {
		if approval {
			fmt.Fprint(t.out, "y 批准本次连接，r 重选回执，q 撤销 > ")
		} else {
			fmt.Fprint(t.out, hostPrompt)
		}
		return
	}
	v := t.view()
	label, keys := "输入回执", "b 返回  q 撤销  p 读取  c 复制  v 显示"
	if approval {
		label, keys = "y 批准本次连接", "r 重选回执  q 撤销"
	}
	fmt.Fprint(t.pageOut(), v.composer(label, v.muted(keys)))
}

// The two reserved rows leave the cursor and any partially typed duration in place.
func (t *Console) showListener(st localssh.Check) {
	v := t.view()
	color, mark := sshIndicator(st)
	detail, _, _ := strings.Cut(st.Detail, "\n")
	fmt.Fprintf(t.out, "\x1b7\x1b[H\x1b[2K%s%s\x1b[2;1H\x1b[2K%s%s\x1b8",
		v.margin, v.ink(color, ansi.Truncate(mark+" "+st.Message, v.width, "…")),
		v.margin, v.muted(ansi.Truncate(detail, v.width, "…")))
}

func (t *Console) askDuration(ctx context.Context, initial localssh.Check) (time.Duration, error) {
	ttl := t.TTL
	var updates <-chan localssh.Check
	if t.fullScreen {
		watch, cancel := context.WithCancel(ctx)
		defer cancel()
		updates = watchListener(watch, t.SSHPort, initial)
		t.clearPage()
		fmt.Fprint(t.out, "\x1b[3;r\x1b[3;1H")
		defer func() {
			fmt.Fprint(t.out, "\x1b[r")
			t.clearPage()
		}()
		t.showListener(initial)
	}
	prompt := fmt.Sprintf("授权时长  1–24 小时或如 30m [回车 %s] > ", ttlLabel(t.TTL))
	if t.terminalUI() {
		prompt = t.view().fieldPrompt(prompt, "q 返回主菜单")
	}
	for {
		fmt.Fprint(t.pageOut(), prompt)
		var item line
	waitInput:
		for {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case st := <-updates:
				initial = st
				t.showListener(st)
			case item = <-t.next():
				t.submitEntry()
				break waitInput
			}
		}
		message := "请输入 1 到 24 的整数小时（或 1m–24h 如 30m），或输入 q 返回。"
		if item.err != nil {
			if _, ok := item.err.(inputIssue); !ok {
				return 0, item.err
			}
			message = item.err.Error()
		} else {
			if strings.EqualFold(item.text, "q") {
				return 0, errBack
			}
			if item.text == "" {
				return ttl, nil
			}
			if d, ok := parseGrantDuration(item.text); ok {
				return d, nil
			}
		}
		if t.fullScreen {
			fmt.Fprint(t.out, "\x1b[3;1H")
			t.showListener(initial)
		}
		t.notice("33", "!", message)
	}
}

func watchListener(ctx context.Context, port int, initial localssh.Check) <-chan localssh.Check {
	updates := make(chan localssh.Check, 1)
	var vacant func() bool
	if !initial.Closed {
		vacant = localssh.VacancyProbe(port)
	}
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		last := initial
		lastProbe := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				// Avoid opening an unauthenticated SSH connection on every tick.
				// Recheck periodically even if a privileged or lingering socket blocks bind.
				if vacant != nil && now.Sub(lastProbe) < 12*time.Second && !vacant() {
					continue
				}
				lastProbe = now
			}
			state := localssh.ProbeListener(ctx, port)
			if state.Closed {
				vacant = nil
			} else if vacant == nil {
				vacant = localssh.VacancyProbe(port)
			}
			if state.Closed && last.Closed || !state.Closed && state.Message == last.Message {
				continue
			}
			last = state
			if state.Closed && port == 22 {
				state.Message = "本机 22 端口已关闭，提交授权时长后将复查临时 SSH。"
			}
			select {
			case updates <- state:
			case <-ctx.Done():
				return
			}
		}
	}()
	return updates
}

func parseGrantDuration(v string) (time.Duration, bool) {
	if n, err := strconv.Atoi(v); err == nil {
		if n >= 1 && n <= 24 {
			return time.Duration(n) * time.Hour, true
		}
		return 0, false
	}
	d, err := time.ParseDuration(strings.ToLower(v))
	if err == nil && d >= time.Minute && d <= grant.MaxTTL {
		return d, true
	}
	return 0, false
}

func ttlLabel(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%d 小时", int(d/time.Hour))
	}
	return d.String()
}
