package console

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/transport"
)

func (t *Console) drawReceipt(ctx context.Context, st active.State, answer grant.Ticket, copyOn, show bool) error {
	t.clearPage()
	t.line("回执中的直连地址 ·", transport.CountCandidates(answer.Claims.SDP))
	if !t.fullScreen {
		t.line("回执文件 ", st.Exchange)
	}
	if err := t.shareTicket(ctx, "回执", answer, copyOn, show); err != nil {
		return err
	}
	// Keep the path and actions below even a screenful of signed text.
	if t.fullScreen {
		t.line("回执文件 ", st.Exchange)
	}
	t.line("有效至   ", st.Deadline.Local().Format("01-02 15:04"))
	showSessionIdentity(t.pageOut(), "本机", answer.Claims.Issuer, answer.Claims.DeviceName)
	t.line("将回执发给被控方。")
	return nil
}

func (t *Console) receiptPrompt(st active.State) {
	v := t.view()
	label := waitForApprovalAndRoute
	hint := "回车复制回执，或输入快捷键后回车"
	if st.Phase == "ready" {
		label = "已连接 · 回车打开 SSH 终端"
		hint = "输入快捷键后回车"
	} else if st.Phase == "disconnected" {
		label = reconnectNotice
	}
	var row string
	for _, label := range []string{"c 复制回执", "v 显示全文", "b 返回"} {
		button := v.key(label)
		if row != "" && ansi.StringWidth(row+"  "+button) > v.width {
			t.line(row)
			row = ""
		}
		if row != "" {
			row += "  "
		}
		row += button
	}
	t.line(row)
	fmt.Fprint(t.out, v.composer(label, hint))
}

func (t *Console) receiptAction(ctx context.Context, keys *receiptKeys, st active.State, answer grant.Ticket) (open bool, err error) {
	cmd, ok, err := keys.poll(t.in)
	if !ok || err != nil {
		return false, err
	}
	switch strings.ToLower(cmd) {
	case "b", "/back", "q":
		return false, errBack
	case "/link":
		return st.Phase == "ready", nil
	case "", "c", "/copy", "v":
		if cmd == "" && st.Phase == "ready" {
			return true, nil
		}
		copyOn := !strings.EqualFold(cmd, "v")
		if err := t.drawReceipt(ctx, st, answer, copyOn, !copyOn); err != nil {
			return false, err
		}
	default:
		t.line("输入 c 复制回执，v 显示全文，或 b 返回。")
	}
	t.receiptPrompt(st)
	return false, nil
}

func (t *Console) waitControl(ctx context.Context, st active.State, text bool) error {
	return t.controlPanel(ctx, st, text, false)
}

type receiptPanelServices struct {
	status func(context.Context, string) (active.State, error)
	link   func(context.Context, active.State) error
}

func (t *Console) controlPanel(ctx context.Context, st active.State, text, review bool) error {
	if st.OneShot {
		return active.ErrOneShot
	}
	tick := time.NewTicker(spinInterval)
	defer tick.Stop()
	return t.receiptPanel(ctx, st, text, review, tick.C, receiptPanelServices{active.Status, t.linkSSH})
}

func (t *Console) receiptPanel(ctx context.Context, st active.State, text, review bool, tick <-chan time.Time, services receiptPanelServices) error {
	t.section = "控制端回执"
	defer t.setActivity("")
	var keys receiptKeys
	var answer *grant.Ticket
	var lastPhase string
	var ticks int
	for {
		panel := st.Exchange != "" && (st.Phase == "waiting" || review && (st.Phase == "ready" || st.Phase == "disconnected"))
		readKeys := (t.terminalUI() || review) && t.in != nil
		if !review && st.Phase == "ready" {
			t.setActivity("")
			t.clearPage()
			t.notice("32", "●", "直连已建立 · "+st.Route)
			if err := services.link(ctx, st); err != nil {
				return fmt.Errorf("SSH 连接结束: %w", err)
			}
			if t.terminalUI() {
				return errBack
			}
			t.line("控制会话已结束。授权期内可再次输入 /link。")
			return nil
		}
		if st.Phase != lastPhase || panel && answer == nil {
			t.setActivity(waitLabel(st))
			switch {
			case panel:
				first := answer == nil
				if first {
					value, err := grant.Read(st.Exchange)
					if err != nil {
						return err
					}
					answer = &value
				}
				if err := t.drawReceipt(ctx, st, *answer, first && t.autoCopy, first && !t.autoCopy && (text || t.interactive)); err != nil {
					return err
				}
				if readKeys {
					t.receiptPrompt(st)
				} else {
					t.line(waitForApprovalAndRoute + "。可在另一个菜单输入 /receipt 再次复制回执。")
				}
			case st.Phase == "disconnected":
				return reconnectingGrant{id: st.ID}
			case st.Phase == "offline":
				return fmt.Errorf("直连已断开，请重新配对 · %s", st.Note)
			default:
				t.clearPage()
				t.line(waitLabel(st) + "…")
			}
			lastPhase = st.Phase
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick:
		}
		t.advanceActivity()
		ticks++
		fresh := st
		if st.Phase == "gathering" || ticks%3 == 0 {
			var err error
			fresh, err = services.status(ctx, t.KeyPath)
			if err != nil {
				return err
			}
			if fresh.ID != st.ID {
				return errors.New("本次授权已结束")
			}
		}
		if panel && fresh.Phase == st.Phase && readKeys {
			open, err := t.receiptAction(ctx, &keys, st, *answer)
			if err != nil {
				return err
			}
			if open {
				review = false
			}
		}
		st = fresh
	}
}
