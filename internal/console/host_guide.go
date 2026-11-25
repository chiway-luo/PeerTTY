package console

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/transport"
)

func (t *Console) showHostGuide(ctx context.Context, st active.State, offer grant.Ticket, copyOn bool) {
	var status string
	if copyOn {
		var err error
		status, err = t.copyTicket(ctx, t.out, offer)
		if err != nil {
			status = "复制失败，可输入 v 查看邀请全文。"
		}
	}
	fmt.Fprint(t.pageOut(), t.view().hostGuide(st, status))
}

// Wrap complete labels and secrets in terminal cells. Indents are outside the
// wrap so a continuation line starts in the same column as the first one.
func (v terminalView) hostLine(indent, value string) string {
	prefix := v.margin + indent
	wrapped := ansi.Wrap(value, max(1, v.width-len(indent)), "-")
	return prefix + strings.ReplaceAll(wrapped, "\n", "\n"+prefix) + "\n"
}

func (v terminalView) hostKey(label string) string {
	key, action, _ := strings.Cut(label, " ")
	return v.key(key) + " " + action
}

func (v terminalView) hostKeys(labels ...string) string {
	var rows strings.Builder
	var row string
	for _, label := range labels {
		button := v.hostKey(label)
		if row != "" && ansi.StringWidth(row+"  "+button) > v.width {
			rows.WriteString(v.hostLine("", row))
			row = ""
		}
		if row != "" {
			row += "  "
		}
		row += button
	}
	rows.WriteString(v.hostLine("", row))
	return rows.String()
}

func (v terminalView) hostGuide(st active.State, copyStatus string) string {
	var b strings.Builder
	compact := v.height < 20 || v.width < 42
	indent, gap := "   ", "\n"
	if compact {
		indent, gap = "", ""
	}
	step := func(n, title string) {
		b.WriteString(v.hostLine("", v.accent(n)+v.bold(title)))
	}
	detail := func(value string) { b.WriteString(v.hostLine(indent, value)) }
	if v.linear {
		b.WriteString(v.hostLine("", v.bold("等待控制端回执")))
	}
	step("1. ", "将邀请私发给对方")
	if copyStatus != "" {
		if !compact && strings.HasPrefix(copyStatus, "已复制") {
			copyStatus += "在与控制方的私聊中粘贴发送。"
		}
		detail(copyStatus)
	}
	if !compact {
		detail(v.hostKey("c 复制邀请") + "  " + v.hostKey("v 显示邀请全文"))
	} else if copyStatus == "" {
		detail("输入 c 复制邀请")
	}
	b.WriteString(gap)
	if compact {
		step("2. ", "另用可信渠道传一次性配对码")
	} else {
		step("2. ", "单独传递一次性配对码")
		detail("换一条已核实对方身份的渠道，例如给对方打电话。")
	}
	code := v.accent(string(st.PairingCode))
	expires := "授权有效至 " + st.Deadline.Local().Format("01-02 15:04")
	if ansi.StringWidth(code+"    "+expires)+len(indent) <= v.width {
		detail(code + "    " + expires)
	} else {
		// On a 36-column terminal the whole code fits if it uses the margins.
		if width := ansi.StringWidth(code); width > v.width && width <= v.width+2*len(v.margin) {
			fmt.Fprintln(&b, code)
		} else {
			detail(code)
		}
		detail(expires)
	}
	if st.Note != "" && !compact {
		detail("本次使用系统 SSH 认证 · 输入 d 查看原因")
	}
	b.WriteString(gap)
	if compact {
		step("3. ", "粘贴回执或输入回执文件路径")
		detail(v.hostKey("p 读取剪贴板回执"))
		b.WriteString(v.composer("输入后按回车", v.hostKey("d 详情与快捷键")))
		return b.String()
	}
	step("3. ", "收到回执后，在下方粘贴")
	detail(v.hostKey("p 读取剪贴板回执") + "  或输入回执文件路径")
	footer := v.hostKey("d 文件与网络详情") + "  " + v.hostKey("b 返回菜单并保留授权") + "  " + v.hostKey("q 撤销本次授权")
	if ansi.StringWidth(footer) > v.width {
		footer = v.hostKey("d 详情与快捷键")
	}
	b.WriteString(v.composer("粘贴回执或输入命令后按回车", footer))
	return b.String()
}

func (t *Console) showHostDetails(st active.State, offer grant.Ticket) {
	v := t.view()
	t.line(v.bold("邀请文件与网络详情"))
	t.line("邀请文件 ", st.Exchange)
	t.line("邀请中的直连地址 ·", transport.CountCandidates(offer.Claims.SDP))
	if st.Note != "" {
		t.line("本次使用系统 SSH 认证 ·", st.Note)
	}
	fmt.Fprint(t.out, v.hostKeys("c 复制邀请", "v 显示邀请全文", "p 读取剪贴板回执", "b 返回菜单并保留授权", "q 撤销本次授权"))
	t.hostDetailsPrompt()
}

func (t *Console) hostDetailsPrompt() {
	v := t.view()
	fmt.Fprint(t.pageOut(), v.composer("回车返回配对步骤", "也可粘贴回执或输入快捷键后回车"))
}

func (t *Console) showCompactHostApproval(v terminalView, offer, answer grant.Ticket) {
	out := t.pageOut()
	if v.linear {
		fmt.Fprint(out, v.hostLine("", "回执已核验 · 等待本机批准"))
	}
	fmt.Fprint(out, v.hostLine("", "请核对控制方回执页上的指纹"))
	showSessionIdentity(out, "控制设备", answer.Claims.Issuer, answer.Claims.DeviceName)
	login := systemAccountScope
	if len(answer.Claims.SSHLoginKey) > 0 {
		login = "批准后可直接登录账号 " + offer.Claims.SSHUser
	}
	fmt.Fprint(out, v.hostLine("", login))
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		fmt.Fprint(out, v.hostLine("", "可按账号已有的 sudo 规则提权"))
	}
	fmt.Fprint(out, v.hostLine("", "授权期内可开多终端，关菜单仍有效"))
	fmt.Fprint(out, v.hostKeys("y 批准本次连接", "r 重选回执", "q 撤销本次授权"))
	fmt.Fprint(out, v.composer("输入后按回车", ""))
}
