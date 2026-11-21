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
		{"授权", []menuAction{statusAction, {"", "/revoke", "撤销授权"}}},
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
		return v.ink("36", "○ ") + "待配对"
	}
	if err != nil {
		return v.ink("33", "! 状态不可用")
	}
	phase := phaseNames[s.Phase]
	if s.Role == "host" && s.Phase == "waiting" {
		phase = "等待回执"
	}
	label := phase + " · " + roleNames[s.Role]
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
	b.WriteString(v.hero(version, system, port, v.grantIndicator(s, err)))
	left, right := connectAction, hostAction
	leftHint, rightHint := "使用对方发来的邀请", "创建邀请并核对回执"
	group := "选择角色"
	if err == nil && s.ID != "" {
		group = "当前授权"
		right, rightHint = statusAction, "查看到期时间和终端数"
		if s.Role == "host" {
			left, leftHint = menuAction{"2", "/host", "被控面板"}, "查看活动与邀请"
		} else {
			left, leftHint = menuAction{"1", "/connect", "继续连接"}, "进入已授权设备的终端"
		}
	}
	if v.height >= 14 {
		fmt.Fprintln(&b, "\n"+v.margin+v.bold(group))
	}
	actionLine := func(a menuAction) string {
		key := v.accent(" › ")
		if a.key != "" {
			key = v.key(a.key)
		}
		return key + " " + v.bold(a.title) + "  " + v.ink("36", a.command)
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
	if v.height < 14 && v.width >= 27 && v.width < 66 {
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
	field := func(name, value string) {
		fmt.Fprintln(&b, v.margin+v.muted(padCells(name, 10))+value)
	}
	if validDeviceName(s.Device) {
		field("对端设备", s.Device)
	}
	field("已连终端", strconv.Itoa(s.Terminals))
	field("授权到期", s.Deadline.Local().Format("01-02 15:04"))
	field("剩余时间", max(time.Duration(0), time.Until(s.Deadline)).Round(time.Second).String())
	if s.Note != "" {
		fmt.Fprintln(&b, v.margin+s.Note)
	}
	return b.String()
}
