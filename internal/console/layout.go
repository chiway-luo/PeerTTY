package console

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"
)

// Widths are terminal cells, including when a line mixes Chinese and ANSI styles.
type terminalView struct {
	width, height int
	margin        string
	color         bool
	linear        bool
}

func newTerminalView(columns, rows int, color bool) terminalView {
	inset := 2
	if columns < 52 {
		inset = 1
	}
	if columns < 28 {
		inset = 0
	}
	return terminalView{width: min(88, max(1, columns-2*inset-1)), height: rows, margin: strings.Repeat(" ", inset), color: color}
}

func (t *Console) view() terminalView {
	columns, rows := 80, 24
	if f, ok := t.out.(*os.File); ok {
		if w, h, err := term.GetSize(int(f.Fd())); err == nil && w > 0 && h > 0 {
			columns, rows = w, h
		} else if t.interactive {
			// Pipe-backed PTYs can expose their dimensions through the shell.
			if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 && n <= 65535 {
				columns = n
			}
			if n, err := strconv.Atoi(os.Getenv("LINES")); err == nil && n > 0 && n <= 65535 {
				rows = n
			}
		}
	}
	v := newTerminalView(columns, rows, t.fullScreen && os.Getenv("NO_COLOR") == "")
	v.linear = !t.fullScreen
	return v
}

func (v terminalView) ink(sgr, text string) string {
	if !v.color || text == "" {
		return text
	}
	return "\x1b[" + sgr + "m" + text + "\x1b[0m"
}

func (v terminalView) accent(text string) string { return v.ink("1;36", text) }
func (v terminalView) bold(text string) string   { return v.ink("1", text) }
func (v terminalView) muted(text string) string  { return v.ink("2", text) }

func (v terminalView) key(text string) string {
	if !v.color {
		return "[" + text + "]"
	}
	return v.ink(brandFill(), " "+text+" ")
}

func padCells(text string, width int) string {
	text = ansi.Truncate(text, width, "…")
	return text + strings.Repeat(" ", max(0, width-ansi.StringWidth(text)))
}

func (v terminalView) rule(left, right string) string {
	gap := max(0, v.width-ansi.StringWidth(left)-ansi.StringWidth(right))
	return v.margin + ansi.Truncate(left+v.muted(strings.Repeat("─", gap))+right, v.width, "")
}

func (v terminalView) heading(title string) string {
	label := v.compactMark() + " " + v.accent("PeerTTY") + v.muted("  /  ") + v.bold(title) + "  "
	if v.height <= 18 {
		return v.rule(label, "") + "\n"
	}
	return v.rule(label, "") + "\n\n"
}

// Draw the footer before placing the cursor. Moving back by rows also works
// when the footer makes the terminal scroll, without taking over line editing.
func (v terminalView) composer(title, footer string) string {
	marker := v.margin + v.accent("❯ ")
	if v.linear {
		return v.margin + title + "\n" + v.margin + footer + "\n" + marker
	}
	if v.height < 18 || v.width < 27 {
		if ansi.StringWidth(title)+ansi.StringWidth(footer)+4 <= v.width {
			return v.rule(title+"  ", "  "+footer) + "\n" + marker
		}
		return v.rule(title+"  ", "") + "\n" + v.margin + ansi.Truncate(footer, v.width, "") + "\n" + marker
	}
	return "\n" + v.rule(v.muted("── ")+title+" ", "") + "\n\n" + v.rule("", "") +
		"\n" + v.margin + ansi.Truncate(footer, v.width, "") + "\x1b[2A\r" + marker
}

func (v terminalView) commandPrompt(home, hasGrant bool) string {
	if !home {
		if v.height < 18 {
			return v.composer("输入下一条命令", v.accent("Enter")+v.muted(" 返回"))
		}
		return v.composer("输入下一条命令", v.accent("Enter")+v.muted(" 返回主菜单"))
	}
	if hasGrant {
		footer := v.accent("/revoke") + v.muted(" 撤销授权   ") + v.accent("?") + v.muted(" 帮助   ") + v.accent("0") + v.muted(" 退出")
		return v.composer("输入命令", footer)
	}
	footer := v.accent("/help") + v.muted(" 全部命令    ") + v.accent("/paste") + v.muted(" 剪贴板    ") +
		v.accent("/status") + v.muted(" 授权状态    ") + v.accent("0") + v.muted(" 退出")
	if ansi.StringWidth(footer) > v.width {
		footer = v.accent("?") + v.muted(" 帮助   ") + v.accent("/paste") + v.muted(" 读取邀请   ") + v.accent("0") + v.muted(" 退出")
	}
	return v.composer("输入命令或粘贴邀请", footer)
}

// Field instructions can contain paths, default values or approval details.
// Keep them in full above the input, including on a narrow terminal.
func (v terminalView) fieldPrompt(prompt, footer string) string {
	label := strings.TrimSuffix(prompt, " > ")
	field, hint, _ := strings.Cut(label, "\n")
	if ansi.StringWidth(field) <= v.width-7 {
		body := ""
		if hint != "" {
			body = v.margin + hint + "\n"
		}
		return body + v.composer(field, v.muted(footer))
	}
	label = strings.ReplaceAll(label, "\n", "\n"+v.margin)
	return v.margin + label + "\n" + v.composer("输入", v.muted(footer))
}

func (v terminalView) panelRow(content string) string {
	return v.margin + v.muted("│") + "  " + padCells(content, v.width-6) + "  " + v.muted("│") + "\n"
}

func (v terminalView) hero(version, system string, port int, status string) string {
	var b strings.Builder
	if version != "" && version != "dev" {
		version = "v" + version
	}
	brand := v.accent("PeerTTY")
	if version != "" {
		brand += " " + v.muted(version)
	}
	title := v.bold("点对点远程终端")
	portLabel := "SSH 端口 " + strconv.Itoa(port)
	if icon := v.brandIcon(); len(icon) > 0 {
		top := v.rule(v.muted("╭"), v.muted("╮"))
		bottom := v.rule(v.muted("╰"), v.muted("╯"))
		labels := [3]string{v.accent("PeerTTY"), title, v.muted(version)}
		details := [3]string{status, v.muted(padCells("本机", 10)) + system, v.muted(padCells("SSH 端口", 10)) + strconv.Itoa(port)}
		wide := v.width >= 66
		if !wide {
			top = v.rule(v.muted("╭─ ")+ansi.Truncate(brand, v.width-6, "…")+" ", v.muted("─╮"))
			bottom = v.rule(v.muted("╰─ ")+status+" ", v.muted("─╯"))
			labels = [3]string{title, system, v.muted(portLabel)}
		}
		fmt.Fprintln(&b, top)
		firstLabel := (len(icon) - len(labels)) / 2
		detailsColumn := max((v.width-6)*3/5, ansi.StringWidth(icon[0])+2+ansi.StringWidth(title)+1)
		for i, line := range icon {
			row := line
			if n := i - firstLabel; n >= 0 && n < len(labels) {
				row += "  " + labels[n]
				if wide {
					row = padCells(row, detailsColumn) + v.muted("│  ") + details[n]
				}
			}
			b.WriteString(v.panelRow(row))
		}
		fmt.Fprintln(&b, bottom)
		return b.String()
	}
	brand = v.compactMark() + " " + brand
	if v.width < 32 || v.height < 13 {
		fmt.Fprintln(&b, v.margin+ansi.Truncate(brand, v.width, "…"))
		fmt.Fprintln(&b, v.margin+title)
		fmt.Fprintln(&b, v.margin+status)
		return b.String()
	}
	fmt.Fprintln(&b, v.rule(v.muted("╭─ ")+ansi.Truncate(brand, v.width-6, "…")+" ", v.muted("─╮")))
	b.WriteString(v.panelRow(title))
	b.WriteString(v.panelRow(v.muted(system + " · " + portLabel)))
	b.WriteString(v.panelRow(status))
	fmt.Fprintln(&b, v.rule(v.muted("╰"), v.muted("╯")))
	return b.String()
}
