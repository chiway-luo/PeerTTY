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

type hostStartServices struct {
	status   func(context.Context, string) (active.State, error)
	ready    func(context.Context) (localssh.Check, error)
	duration func(context.Context, localssh.Check) (time.Duration, error)
	start    func(context.Context, active.Options) (active.State, error)
	watch    func(context.Context, active.State) error
}

func (t *Console) host(ctx context.Context) error {
	return t.hostWith(ctx, hostStartServices{active.Status, t.hostReady, t.askDuration, active.Start, t.watchHost})
}

func (t *Console) hostWith(ctx context.Context, services hostStartServices) error {
	if current, err := services.status(ctx, t.KeyPath); err == nil {
		if current.OneShot {
			return active.ErrOneShot
		}
		if current.Role == "host" {
			return services.watch(ctx, current)
		}
		return grant.ErrInUse
	} else if !errors.Is(err, active.ErrInactive) {
		return err
	}
	if !t.terminalUI() {
		fmt.Fprintln(t.out, "允许被控制 · 输入 q 返回")
	}
	initial, err := services.ready(ctx)
	if err != nil {
		return err
	}
	ttl, err := services.duration(ctx, initial)
	if err != nil {
		return err
	}
	current, err := services.ready(ctx)
	if err != nil {
		return err
	}
	st, err := services.start(ctx, active.Options{Role: "host", Key: t.KeyPath, Port: t.SSHPort, TTL: ttl, STUN: t.STUN, RequireScoped: current.ScopedOnly})
	if err != nil {
		return err
	}
	return services.watch(ctx, st)
}

const hostPrompt = "回执 / p 读取 / c 复制 / v 显示 / b 返回 / q 撤销 > "
const systemAccountScope = "系统 SSH 策略决定可登录账号"

type hostPanelServices struct {
	status  func(context.Context, string) (active.State, error)
	revoke  func(context.Context, string, string) error
	approve func(context.Context, string, string, grant.Ticket) error
}

func (t *Console) watchHost(ctx context.Context, st active.State) error {
	spin := time.NewTicker(spinInterval)
	defer spin.Stop()
	poll := time.NewTicker(600 * time.Millisecond)
	defer poll.Stop()
	return t.hostPanel(ctx, st, spin.C, poll.C, hostPanelServices{active.Status, active.Revoke, active.Approve})
}

func (t *Console) hostPanel(ctx context.Context, st active.State, spin, poll <-chan time.Time, services hostPanelServices) error {
	t.section = "被控面板"
	defer t.setActivity("")
	var offer grant.Ticket
	var pending *grant.Ticket
	var input <-chan line
	var previous active.State
	var previousView terminalView
	for {
		if st.Phase == "offline" {
			return t.endHostPrompt(ctx, st, "", errors.New(st.Note))
		}
		live := st.Phase == "ready" || st.Phase == "disconnected" || st.Phase == "connecting"
		changed := st.Phase != previous.Phase
		var view terminalView
		if live {
			view = t.view()
			changed = changed || view != previousView || grantFactsChanged(st, previous) || t.editStatus != ""
		}
		if changed && live && !t.lineEdit.tryLock() {
			t.showEditStatus(view, st, nil, "")
		} else if changed {
			t.setStatusRow(waitLabel(st), grantClock(st))
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
				if t.terminalUI() {
					t.showHostGuide(ctx, st, offer, t.autoCopy)
				} else {
					t.describeOffer(st, offer)
					if err = t.shareTicket(ctx, "邀请", offer, t.autoCopy, true); err != nil {
						return err
					}
					t.line("将邀请私发给对方，再粘贴回执或输入文件路径。")
					fmt.Fprint(t.out, hostPrompt)
				}
			}
			if live {
				t.drawLiveHost(st)
				previousView = view
				t.lineEdit.unlock()
			}
			previous = st
		}
		if t.editStatus == "" && t.fullScreen {
			t.setStatusRow(t.activity, grantClock(st))
		}
		if input == nil && st.Phase != "gathering" {
			input = t.next()
		}
		pollInterval := poll
		if st.Phase == "gathering" {
			pollInterval = nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-spin:
			t.advanceActivity()
			if st.Phase != "gathering" {
				continue
			}
			fresh, err := services.status(ctx, t.KeyPath)
			if err != nil || fresh.ID != st.ID {
				return t.handleHostEnded(ctx, st, err)
			}
			st = fresh
		case <-pollInterval:
			fresh, err := services.status(ctx, t.KeyPath)
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
			cmd := strings.ToLower(item.text)
			guide := t.terminalUI() && st.Phase == "waiting" && pending == nil
			if guide && cmd == "d" {
				t.showHostDetails(st, offer)
				continue
			}
			switch cmd {
			case "b", "/back":
				if !t.fullScreen {
					fmt.Fprintln(t.out, "授权继续有效。输入 /revoke 可撤销。")
				}
				return errBack
			case "q", "/revoke":
				if err := services.revoke(ctx, t.KeyPath, st.ID); err != nil {
					return err
				}
				t.notice("32", "✓", "本次授权已撤销。")
				return nil
			case "v", "c":
				if st.Phase != "waiting" {
					break
				}
				if guide && cmd == "c" {
					t.showHostGuide(ctx, st, offer, true)
					continue
				}
				if err := t.shareTicket(ctx, "邀请", offer, cmd == "c", cmd == "v"); err != nil {
					return err
				}
				if guide {
					t.hostDetailsPrompt()
					continue
				}
			default:
				if st.Phase != "waiting" {
					if isTicketText(item.text) {
						t.notice("33", "!", "本次授权已绑定控制端，无法更换回执。")
					}
					break
				}
				if pending != nil {
					if strings.EqualFold(item.text, "y") {
						if err := services.approve(ctx, t.KeyPath, st.ID, *pending); err != nil {
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
	message := "被控会话已结束。"
	if st.TimeLeft() <= 0 {
		message = "授权已到期。"
		err = active.WaitEnded(ctx, t.KeyPath, st.ID)
	} else if err == nil || errors.Is(err, active.ErrInactive) {
		err = nil
		if reason, _, ok := active.LastError(t.KeyPath); ok {
			err = errors.New(reason)
		}
	}
	return t.endHostPrompt(ctx, st, message, err)
}

func (t *Console) endHostPrompt(ctx context.Context, st active.State, message string, err error) error {
	if t.pending != nil {
		if !t.lineEdit.tryLock() {
			// Show the result now. The main menu will reuse the pending entry.
			notice := message
			if err != nil {
				notice = err.Error()
			}
			t.showEditStatus(t.view(), st, err, notice)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case t.lineEdit.owner <- struct{}{}:
			}
		}
		defer t.lineEdit.unlock()
	}
	t.clearPage()
	if err == nil {
		t.line(message)
	}
	return err
}

func (t *Console) describeOffer(st active.State, offer grant.Ticket) {
	t.line("邀请中的直连地址 ·", transport.CountCandidates(offer.Claims.SDP))
	t.line("邀请文件 ", st.Exchange)
	t.line("有效至   ", st.Deadline.Local().Format("01-02 15:04"))
	t.line("一次性配对码  ", st.PairingCode)
	t.line("通过电话或另一条已确认对方身份的渠道，将配对码单独交给控制方。")
	if st.Note != "" {
		t.line("本次使用系统 SSH 认证 ·", st.Note)
	}
}

func (t *Console) drawLiveHost(st active.State) {
	v := t.view()
	switch st.Phase {
	case "connecting":
		t.line("已批准本次连接。正在检查 UDP 和 TCP 直连路径。")
	case "ready":
		if t.terminalUI() {
			t.notice("32", "●", "被控会话已连接")
		} else {
			t.line("被控会话已连接 · " + st.Route)
			t.line("b 返回，q 撤销并关闭全部终端。")
			t.line("已连接终端 ", st.Terminals)
		}
	case "disconnected":
		t.notice("33", "!", reconnectNotice)
	}
	if t.terminalUI() {
		fmt.Fprint(t.pageOut(), v.grantFacts(st, true))
	}
	if st.Note != "" {
		t.line(st.Note)
	}
	if t.terminalUI() {
		fmt.Fprint(t.pageOut(), v.composer("输入面板命令", v.muted("b 返回  q 撤销并关闭全部终端")))
	}
}

func (t *Console) hostInputPrompt(st active.State, offer grant.Ticket, pending *grant.Ticket) {
	if st.Phase != "waiting" {
		if t.terminalUI() {
			t.drawLiveHost(st)
		} else {
			printStatus(t.out, st)
		}
		return
	}
	if pending == nil {
		if t.terminalUI() {
			t.setStatusRow(waitLabel(st), grantClock(st))
			fmt.Fprint(t.pageOut(), t.view().hostGuide(st, ""))
		} else {
			fmt.Fprint(t.out, hostPrompt)
		}
		return
	}
	t.setStatusRow("回执已核验 · 等待本机批准", grantClock(st))
	v := t.view()
	if t.terminalUI() && (v.height < 18 || v.width < 32) {
		t.showCompactHostApproval(v, offer, *pending)
		return
	}
	showSessionIdentity(t.pageOut(), "请求控制的设备", pending.Claims.Issuer, pending.Claims.DeviceName)
	t.line("可与控制方回执页上的本次会话指纹核对。")
	t.notice("32", "✓", "回执已核验。关闭菜单后，此设备仍可在授权期内打开多个终端。")
	if len(pending.Claims.SSHLoginKey) > 0 {
		fmt.Fprintf(t.out, "批准后可直接登录当前账号 %s。\n", offer.Claims.SSHUser)
	} else {
		fmt.Fprintln(t.out, "批准后允许这台设备连接本机 SSH。"+systemAccountScope+"，每次登录均需通过系统认证。")
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		fmt.Fprintln(t.out, "登录后，对方可以按该账号已有的 sudo 规则执行管理员命令。")
	}
	if !t.terminalUI() {
		fmt.Fprint(t.out, "y 批准本次连接，r 重选回执，q 撤销 > ")
		return
	}
	fmt.Fprint(t.pageOut(), v.hostKeys("y 批准本次连接", "r 重选回执", "q 撤销本次授权"))
	fmt.Fprint(t.out, v.composer("核对设备后输入选择", "按回车确认"))
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
	return t.askDurationWith(ctx, initial, watchListener)
}

func (t *Console) askDurationWith(ctx context.Context, initial localssh.Check, subscribe func(context.Context, int, localssh.Check) <-chan localssh.Check) (time.Duration, error) {
	ttl := t.TTL
	var updates <-chan localssh.Check
	if t.fullScreen {
		watch, cancel := context.WithCancel(ctx)
		defer cancel()
		updates = subscribe(watch, t.SSHPort, initial)
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
		watchListenerEvents(ctx, port, initial, vacant, localssh.VacancyProbe, localssh.ProbeListener, time.Now(), tick.C, updates)
	}()
	return updates
}

func watchListenerEvents(ctx context.Context, port int, initial localssh.Check, vacant func() bool,
	makeVacancy func(int) func() bool, probe func(context.Context, int) localssh.Check,
	lastProbe time.Time, ticks <-chan time.Time, updates chan<- localssh.Check) {
	last := initial
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticks:
			// Avoid opening an unauthenticated SSH connection on every tick.
			// Recheck periodically even if a privileged or lingering socket blocks bind.
			if vacant != nil && now.Sub(lastProbe) < 12*time.Second && !vacant() {
				continue
			}
			lastProbe = now
		}
		state := probe(ctx, port)
		if state.Closed {
			vacant = nil
		} else if vacant == nil {
			vacant = makeVacancy(port)
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
