package console

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
)

func TestTerminalPagesShareLayoutWithoutCursorControls(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	v := newTerminalView(80, 24, false)
	s := active.State{ID: "current", Role: "control", Phase: "waiting", Exchange: "session.answer"}
	for _, page := range []menuPage{homePage, helpPage, statusPage} {
		var full, linear bytes.Buffer
		c := Console{out: &full, fullScreen: true, section: "菜单"}
		c.drawMenu(v, page, s, nil)
		c.out, c.fullScreen = &linear, false
		c.drawMenu(v, page, s, nil)
		if linear.String() != ansi.Strip(full.String()) {
			t.Fatalf("different content in full-screen and plain terminals on page %d", page)
		}
	}
}

func TestMenuColorsMatchTerminalCapabilities(t *testing.T) {
	t.Setenv("WT_SESSION", "")
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

func TestBrandIconKeepsSmallWindowsAndTransparentCutouts(t *testing.T) {
	// Two square pixels fit vertically in one terminal cell. Spaces should
	// show the actual terminal background, including inside the chevron.
	want := []string{
		"      ##########",
		"      #        #",
		"      #        #",
		"      #        #",
		"      #  ####  #",
		"      #        #",
		"#########      #",
		"###  ####      #",
		"####  ##########",
		"#####  ##       ",
		"####  ###       ",
		"###  ####       ",
		"#########       ",
		"#########       ",
	}
	halves := [...]*strings.Replacer{
		strings.NewReplacer("█", "#", "▀", "#", "▄", " "),
		strings.NewReplacer("█", "#", "▀", " ", "▄", "#"),
	}
	for _, size := range [][2]int{{80, 24}, {120, 30}, {180, 60}} {
		v := newTerminalView(size[0], size[1], false)
		mono := v.brandIcon()
		if len(mono) != 7 {
			t.Errorf("%dx%d icon has %d rows, want 7", size[0], size[1], len(mono))
			continue
		}
		v.color = true
		colored := v.brandIcon()
		if len(colored) != len(mono) {
			t.Fatalf("colored icon has %d rows, want %d", len(colored), len(mono))
		}
		for y, row := range mono {
			if ansi.StringWidth(row) != 16 {
				t.Fatalf("row %d has %d cells, want 16", y, ansi.StringWidth(row))
			}
			for half, blocks := range halves {
				pixels := blocks.Replace(row)
				if pixels != want[y*2+half] {
					t.Errorf("pixel row %d: %q, want %q", y*2+half, pixels, want[y*2+half])
				}
			}
			// Only the front window receives a foreground colour.
			expectColor := row
			if y >= 3 {
				cells := []rune(row)
				expectColor = "\x1b[36m" + string(cells[:9]) + "\x1b[0m" + string(cells[9:])
			}
			if colored[y] != expectColor {
				t.Errorf("unexpected icon color or background in row %d: %q", y, colored[y])
			}
		}
	}
}

func TestMenuFitsTerminal(t *testing.T) {
	for _, size := range [][2]int{{36, 12}, {38, 18}, {40, 20}, {46, 24}, {52, 14}, {60, 21}, {71, 18}, {80, 24}, {84, 21}, {120, 30}, {120, 36}} {
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
				if v.width >= 38 && v.height >= 21 {
					words = append(words, "2222")
				} else {
					words = append(words, "▄▀ PeerTTY")
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
				if !strings.Contains(help, "▄▀ PeerTTY") {
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
