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

	"peertty/internal/active"
	"peertty/internal/grant"
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
	if !t.fullScreen {
		fmt.Fprintln(t.out, "允许被控制 · 输入 q 返回")
	}
	if err := t.hostReady(ctx); err != nil {
		return err
	}
	ttl, err := t.askDuration(ctx)
	if err != nil {
		return err
	}
	st, err := active.Start(ctx, active.Options{Role: "host", Key: t.KeyPath, Port: t.SSHPort, TTL: ttl, STUN: t.STUN})
	if err != nil {
		return err
	}
	return t.watchHost(ctx, st)
}

const hostPrompt = "回执 / p 读取 / c 复制 / v 显示 / b 返回 / q 撤销 > "

func (t *Console) watchHost(ctx context.Context, st active.State) error {
	t.section = "被控面板"
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	var offer grant.Ticket
	var pending *grant.Ticket
	var input <-chan line
	var previous active.State
	for {
		if st.Phase != previous.Phase || (st.Phase == "ready" && st != previous) {
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
				if !t.fullScreen {
					t.describeOffer(st, offer)
				}
				if err = shareTicket(ctx, t.pageOut(), "邀请", offer, t.autoCopy, !t.interactive); err != nil {
					return err
				}
				if t.fullScreen {
					t.describeOffer(st, offer)
				}
				t.line("将邀请私发给对方，再粘贴回执或输入文件路径。")
				t.writeHostPrompt(false)
			case "connecting":
				t.line("已批准本次连接。正在进行双向 UDP 探测。")
			case "ready":
				t.notice("32", "●", "被控会话已连接 · "+st.Route)
				if !t.fullScreen {
					t.line("b 返回，q 撤销并关闭全部终端。")
				}
				if st.Note != "" {
					t.line(st.Note)
				}
				t.line("已连接终端 ", st.Terminals)
			case "disconnected":
				t.notice("33", "!", "直连暂时中断，正在等待原路径恢复。")
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
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			fresh, err := active.Status(ctx, t.KeyPath)
			if err != nil || fresh.ID != st.ID {
				t.clearPage()
				if time.Until(st.Deadline) <= 0 {
					t.line("授权已到期。")
					return nil
				}
				if err != nil && !errors.Is(err, active.ErrInactive) {
					return err
				}
				t.line("被控会话已结束。")
				return nil
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
					if err := shareTicket(ctx, t.pageOut(), "邀请", offer, strings.EqualFold(item.text, "c"), strings.EqualFold(item.text, "v")); err != nil {
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
						err = answer.VerifyAnswer(offer, time.Now())
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

func (t *Console) describeOffer(st active.State, offer grant.Ticket) {
	t.line("邀请中的直连地址 ·", transport.CountCandidates(offer.Claims.SDP))
	t.line("邀请文件 ", st.Exchange)
	t.line("有效至   ", st.Deadline.Local().Format("01-02 15:04"))
	if st.Note != "" {
		t.line("本次使用系统 SSH 认证 ·", st.Note)
	}
}

func (t *Console) liveHostPrompt() {
	if t.fullScreen {
		v := t.view()
		fmt.Fprint(t.pageOut(), v.composer("输入面板命令", v.muted("b 返回  q 撤销并关闭全部终端")))
	}
}

func (t *Console) hostInputPrompt(st active.State, offer grant.Ticket, pending *grant.Ticket) {
	if st.Phase != "waiting" {
		if t.fullScreen {
			fmt.Fprint(t.pageOut(), t.view().status(st, nil))
			t.liveHostPrompt()
		} else {
			printStatus(t.out, st)
		}
		return
	}
	if pending == nil {
		if t.fullScreen {
			t.describeOffer(st, offer)
		}
		t.writeHostPrompt(false)
		return
	}
	showDeviceName(t.pageOut(), "请求控制的设备", pending.Claims.DeviceName)
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
	if !t.fullScreen {
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

func (t *Console) askDuration(ctx context.Context) (time.Duration, error) {
	ttl := t.TTL
	for {
		v, err := t.prompt(ctx, fmt.Sprintf("授权时长  1–24 小时 [回车 %s] > ", ttlLabel(t.TTL)))
		if err != nil {
			return 0, err
		}
		if v == "" {
			break
		}
		n, err := strconv.Atoi(v)
		if err == nil && n >= 1 && n <= 24 {
			ttl = time.Duration(n) * time.Hour
			break
		}
		t.notice("33", "!", "请输入 1 到 24 的整数小时，或输入 q 返回。")
	}
	return ttl, nil
}

func ttlLabel(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%d 小时", int(d/time.Hour))
	}
	return d.String()
}
