package console

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
)

func TestMenuColorsMatchTerminalCapabilities(t *testing.T) {
	for _, tc := range []struct{ term, colors, fill string }{
		{"xterm", "", "1;30;106"}, {"xterm-256color", "", "1;38;5;16;48;5;86"},
		{"xterm-256color", "truecolor", "1;38;2;15;15;16;48;2;92;243;198"},
	} {
		t.Setenv("TERM", tc.term)
		t.Setenv("COLORTERM", tc.colors)
		t.Setenv("NO_COLOR", "")
		c := Console{fullScreen: true}
		if got := c.view().key("1"); !strings.Contains(got, "\x1b["+tc.fill+"m") || ansi.Strip(got) != " 1 " {
			t.Fatalf("%s/%s: %q", tc.term, tc.colors, got)
		}
		t.Setenv("NO_COLOR", "1")
		if got := c.view().key("1"); got != "[1]" {
			t.Fatalf("monochrome key: %q", got)
		}
	}
}

func TestMenuFitsTerminal(t *testing.T) {
	for _, size := range [][2]int{{36, 12}, {38, 18}, {40, 20}, {52, 14}, {60, 21}, {71, 18}, {84, 21}, {120, 36}} {
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
				home := check("home", v.home("0.3.1+test", 2222, active.State{}, active.ErrInactive)+v.commandPrompt(true, false))
				words := []string{"点对点远程终端", "待配对", "/connect", "/host", "v0.3.1+test"}
				if v.width >= 35 && v.height >= 18 {
					words = append(words, "┏━━━━━┓", "┃  ━━ ┃", "┗━━━┛", "2222")
				} else {
					words = append(words, "❯_ PeerTTY")
				}
				for _, word := range words {
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
				if !strings.Contains(help, "❯_ PeerTTY") {
					t.Error("help missing compact brand")
				}
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
