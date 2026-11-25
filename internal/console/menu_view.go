package console

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
)

type menuAction struct{ key, command, title string }

var (
	connectAction = menuAction{"1", "/connect", "控制设备"}
	hostAction    = menuAction{"2", "/host", "允许被控制"}
	statusAction  = menuAction{"", "/status", "授权状态"}
	helpGroups    = []struct {
		title   string
		actions []menuAction
	}{
		{"连接", []menuAction{connectAction, hostAction, {"", "/paste", "读取剪贴板邀请"}, {"", "/link", "打开 SSH 终端"}}},
		{"授权", []menuAction{statusAction, {"", "/receipt", "查看控制端回执"}, {"", "/revoke", "撤销授权"}}},
		{"本机", []menuAction{{"3", "/settings", "连接设置"}, {"4", "/doctor", "网络自检"}, {"5", "/check", "检查被控条件"}, {"", "/clipboard", "切换自动复制"}, {"0", "/quit", "关闭菜单"}}},
	}
)

func menuCommand(s string) (command, title string) {
	switch s {
	case "?", "/", "/help":
		return "/help", "全部操作"
	case "q", "Q", "/exit":
		return "/quit", "关闭菜单"
	case "p", "P":
		s = "/paste"
	}
	for _, group := range helpGroups {
		for _, action := range group.actions {
			if s == action.command || (action.key != "" && s == action.key) {
				return action.command, action.title
			}
		}
	}
	return s, ""
}

func (v terminalView) grantIndicator(s active.State, err error) string {
	if errors.Is(err, active.ErrInactive) {
		return v.ink("36", "○ ") + "待配对 · 暂无授权"
	}
	if err != nil {
		return v.ink("33", "! 状态不可用")
	}
	label := phaseName(s) + " · " + roleNames[s.Role]
	if s.Phase == "ready" {
		return v.ink("32", "● "+label)
	}
	return v.ink("33", "◌ "+label)
}

func (v terminalView) home(version string, port int, s active.State, err error) string {
	system := map[string]string{"darwin": "macOS", "windows": "Windows", "linux": "Linux"}[runtime.GOOS]
	if system == "" {
		system = runtime.GOOS
	}
	var b strings.Builder
	actionLine := func(a menuAction) string {
		return v.key(a.key) + " " + v.bold(a.title) + "  " + v.ink("36", a.command)
	}
	indicator := v.grantIndicator(s, err)
	if err == nil && s.ID != "" {
		if v.height >= 24 {
			b.WriteString(v.hero(version, system, port, indicator))
			fmt.Fprintln(&b, v.margin+v.bold("当前授权"))
		} else {
			b.WriteString(v.heading("当前授权"))
			fmt.Fprintln(&b, v.margin+indicator)
		}
		b.WriteString(v.grantFacts(s, true))
		if s.Note != "" {
			note, _, _ := strings.Cut(s.Note, "\n")
			fmt.Fprintln(&b, v.margin+ansi.Truncate(note, v.width, "…"))
		}
		action, hint := menuAction{"2", "/host", "被控面板"}, "查看活动与邀请"
		if s.Role == "control" {
			action, hint = menuAction{"1", "/connect", "继续连接"}, "/receipt 查看或复制回执"
			if s.Phase == "waiting" {
				hint = "/receipt 查看或再复制回执"
			}
		}
		fmt.Fprintln(&b, v.margin+actionLine(action))
		if v.height >= 18 {
			fmt.Fprintln(&b, v.margin+"    "+v.muted(hint))
		}
		return b.String()
	}
	b.WriteString(v.hero(version, system, port, indicator))
	left, right := connectAction, hostAction
	leftHint, rightHint := "使用对方发来的邀请", "创建邀请并核对回执"
	if v.height >= 14 {
		fmt.Fprintln(&b, "\n"+v.margin+v.bold("选择角色"))
	}
	if v.width >= 61 {
		col := (v.width - 3) / 2
		divider := v.muted(" │ ")
		fmt.Fprintln(&b, v.margin+padCells(actionLine(left), col)+divider+actionLine(right))
		if v.height >= 16 {
			fmt.Fprintln(&b, v.margin+padCells("    "+v.muted(leftHint), col)+divider+"    "+v.muted(rightHint))
		}
	} else {
		fmt.Fprintln(&b, v.margin+actionLine(left))
		if v.height >= 18 {
			fmt.Fprintln(&b, v.margin+"    "+v.muted(leftHint))
		}
		fmt.Fprintln(&b, v.margin+actionLine(right))
		if v.height >= 18 {
			fmt.Fprintln(&b, v.margin+"    "+v.muted(rightHint))
		}
	}
	return b.String()
}

func (v terminalView) help() string {
	if v.height <= 14 && v.width >= 27 && v.width < 66 {
		// With very few rows, keep every command reachable on a single screen.
		var entries []string
		col := (v.width - 3) / 2
		for _, group := range helpGroups {
			for _, a := range group.actions {
				key := "  "
				if a.key != "" {
					key = v.accent(a.key) + " "
				}
				entry := key + v.ink("36", a.command)
				if ansi.StringWidth(entry+" "+a.title) <= col {
					entry += " " + a.title
				}
				entries = append(entries, entry)
			}
		}
		var b strings.Builder
		for i := 0; i < len(entries); i += 2 {
			row := entries[i]
			if i+1 < len(entries) {
				row = padCells(row, col) + v.muted(" │ ") + entries[i+1]
			}
			fmt.Fprintln(&b, v.margin+row)
		}
		return b.String()
	}
	var groups [][]string
	for _, group := range helpGroups {
		var rows []string
		if v.height >= 23 || v.width >= 66 {
			rows = append(rows, v.bold(group.title))
		}
		for _, a := range group.actions {
			key := "   "
			if a.key != "" {
				key = " " + v.accent(a.key) + " "
			}
			rows = append(rows, key+" "+padCells(v.ink("36", a.command), 11)+" "+a.title)
		}
		groups = append(groups, rows)
	}
	var b strings.Builder
	if v.width >= 66 {
		left := append(groups[0], "")
		left = append(left, groups[1]...)
		right := groups[2]
		for i := range max(len(left), len(right)) {
			var leftRow, rightRow string
			if i < len(left) {
				leftRow = left[i]
			}
			if i < len(right) {
				rightRow = right[i]
			}
			fmt.Fprintln(&b, v.margin+padCells(leftRow, (v.width-3)/2)+v.muted(" │ ")+rightRow)
		}
	} else {
		for i, group := range groups {
			if i > 0 && v.height >= 23 {
				fmt.Fprintln(&b)
			}
			for _, row := range group {
				fmt.Fprintln(&b, v.margin+row)
			}
		}
	}
	return b.String()
}

func (v terminalView) status(s active.State, err error) string {
	if errors.Is(err, active.ErrInactive) {
		return v.margin + v.muted("○ ") + "当前没有有效的 PeerTTY 授权\n" +
			v.margin + v.ink("36", "/connect") + " 控制设备    " + v.ink("36", "/host") + " 创建邀请\n"
	}
	if err != nil {
		return v.margin + v.ink("33", "! ") + err.Error() + "\n"
	}
	var b strings.Builder
	fmt.Fprintln(&b, v.margin+v.grantIndicator(s, nil))
	b.WriteString(v.grantFacts(s, false))
	if s.Note != "" {
		fmt.Fprintln(&b, v.margin+s.Note)
	}
	if s.Role == "control" && s.Exchange != "" && s.Phase != "offline" {
		fmt.Fprintln(&b, v.margin+v.ink("36", "/receipt")+" 查看或复制本次回执")
	}
	if s.Role == "control" && (s.Phase == "ready" || s.Phase == "disconnected") {
		fmt.Fprintln(&b, v.margin+v.ink("36", "/link")+" 直连可用时打开 SSH 终端")
	}
	if s.Phase == "disconnected" {
		fmt.Fprintln(&b, v.margin+v.ink("36", "/revoke")+" 结束授权并重新配对")
	}
	return b.String()
}

func grantFactsChanged(s, last active.State) bool {
	return s.Terminals != last.Terminals || s.Device != last.Device || s.Route != last.Route ||
		!s.Deadline.Equal(last.Deadline) || s.Note != last.Note
}

func (v terminalView) grantFacts(s active.State, inline bool) string {
	var b strings.Builder
	field := func(name, value string) {
		if inline {
			value = ansi.Truncate(value, max(1, v.width-10), "…")
		}
		fmt.Fprintln(&b, v.margin+v.muted(padCells(name, 10))+value)
	}
	if validDeviceName(s.Device) {
		field("对端设备", s.Device)
	}
	field("已连终端", strconv.Itoa(s.Terminals))
	if s.Route != "" {
		field("直连路径", s.Route)
	}
	if !s.Deadline.IsZero() {
		field("授权到期", s.Deadline.Local().Format("01-02 15:04"))
		if !inline || v.linear {
			field("剩余时间", s.TimeLeft().Round(time.Second).String())
		}
	}
	return b.String()
}
