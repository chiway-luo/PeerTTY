package console

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
)

func TestMenuFitsTerminal(t *testing.T) {
	for _, size := range [][2]int{{36, 12}, {40, 20}, {52, 14}, {60, 21}, {84, 21}, {120, 36}} {
		for _, color := range []bool{true, false} {
			t.Run(fmt.Sprintf("%dx%d/color=%t", size[0], size[1], color), func(t *testing.T) {
				v := newTerminalView(size[0], size[1], color)
				check := func(name, body string) string {
					t.Helper()
					if !color && strings.Contains(body, "\x1b[0m") {
						t.Fatalf("%s has color in monochrome mode", name)
					}
					visible := ansi.Strip(body)
					rows := strings.Split(visible, "\n")
					if len(rows) > size[1] {
						t.Errorf("%s requires %d rows, have %d", name, len(rows), size[1])
					}
					for _, row := range rows {
						// The composer returns to the editing row after writing its footer.
						for _, segment := range strings.Split(row, "\r") {
							if cells := ansi.StringWidth(segment); cells >= size[0] {
								t.Errorf("%s wraps a %d-cell row: %q", name, cells, segment)
							}
						}
					}
					return visible
				}
				home := check("home", v.home("0.3.1+ui.2", 2222, active.State{}, active.ErrInactive)+v.commandPrompt(true, false))
				for _, word := range []string{"待配对", "/connect", "/host", "❯"} {
					if !strings.Contains(home, word) {
						t.Errorf("home missing %q", word)
					}
				}
				for _, row := range strings.Split(home, "\n") {
					if strings.Contains(row, "/connect") && strings.Contains(row, "/host") != (v.width >= 61) {
						t.Errorf("wrong role layout: %q", row)
					}
				}
				help := check("help", v.heading("全部操作")+v.help()+v.commandPrompt(false, false))
				for _, group := range helpGroups {
					for _, a := range group.actions {
						cmd, _ := menuCommand(a.key)
						if !strings.Contains(help, a.command) || (a.key != "" && cmd != a.command) {
							t.Errorf("missing command or shortcut: %+v", a)
						}
					}
				}
			})
		}
	}
}

func TestHomeShowsCurrentGrant(t *testing.T) {
	v := newTerminalView(80, 24, false)
	for _, tc := range []struct{ role, phase, action, state string }{
		{"control", "ready", "继续连接", "已连接 · 控制端"},
		{"host", "waiting", "被控面板", "等待回执 · 被控端"},
	} {
		s := active.State{ID: "example", Role: tc.role, Phase: tc.phase}
		screen := v.home("dev", 22, s, nil) + v.commandPrompt(true, true)
		for _, word := range []string{"当前授权", tc.action, tc.state, "/status", "/revoke"} {
			if !strings.Contains(screen, word) {
				t.Errorf("%s %s missing %q", tc.role, tc.phase, word)
			}
		}
	}
}
