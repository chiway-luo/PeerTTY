package console

import (
	"errors"
	"os"
	"strings"
	"testing"

	"peertty/internal/active"
)

func TestTerminalDimensionsFallbackOnlyForInteractiveFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "redirected")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, tc := range []struct {
		cols, rows, color              string
		interactive, screen, wantColor bool
		width, height                  int
	}{
		{"42", "17", "", true, true, true, 39, 17},
		{"42", "17", "1", true, true, false, 39, 17},
		{"42", "17", "", false, false, false, 75, 24},
		{"invalid", "invalid", "", true, false, false, 75, 24},
		{"0", "0", "", true, false, false, 75, 24},
		{"65536", "65536", "", true, false, false, 75, 24},
	} {
		t.Setenv("COLUMNS", tc.cols)
		t.Setenv("LINES", tc.rows)
		t.Setenv("NO_COLOR", tc.color)
		ui := Console{out: file, interactive: tc.interactive, fullScreen: tc.screen}
		got := ui.view()
		if got.width != tc.width || got.height != tc.height || got.color != tc.wantColor || got.linear == tc.screen {
			t.Fatalf("columns=%q rows=%q: layout=%+v", tc.cols, tc.rows, got)
		}
	}
}

func TestTerminalComposerKeepsShortInstructionsOnOneLine(t *testing.T) {
	view := newTerminalView(36, 12, false)
	if out := view.composer("输入", "回车"); strings.Count(out, "\n") != 1 || !strings.Contains(out, "回车") {
		t.Fatalf("unexpected layout for short prompt: %q", out)
	}
	instructions := "请粘贴很长的完整邀请文字或者输入邀请文件的绝对路径"
	if out := view.fieldPrompt(instructions+"\n不截断路径 > ", "返回"); !strings.Contains(out, instructions) || !strings.Contains(out, "不截断路径") {
		t.Fatalf("narrow prompt lost instructions: %q", out)
	}
	if out := view.hero("dev", "macOS", 22, "空闲"); !strings.Contains(out, "dev") || strings.Contains(out, "vdev") {
		t.Fatalf("development version mislabeled: %q", out)
	}
}

func TestMenuAliasesRespectIntentWithoutRewritingOtherInput(t *testing.T) {
	for _, tc := range []struct{ input, command, title string }{
		{"?", "/help", "全部操作"},
		{"/", "/help", "全部操作"},
		{"Q", "/quit", "关闭菜单"},
		{"P", "/paste", "读取剪贴板邀请"},
		{"2", "/host", "允许被控制"},
		{"/exit", "/quit", "关闭菜单"},
		{"./invite", "./invite", ""},
	} {
		if command, title := menuCommand(tc.input); command != tc.command || title != tc.title {
			t.Fatalf("menuCommand(%q) = %q, %q", tc.input, command, title)
		}
	}
}

func TestAuthViewsExposeOnlyApplicableActions(t *testing.T) {
	v := newTerminalView(50, 20, false)
	for _, tc := range []struct {
		role, phase                       string
		showLink, showReceipt, showRevoke bool
	}{
		{"control", "ready", true, true, false},
		{"control", "waiting", false, true, false},
		{"control", "offline", false, false, false},
		{"control", "disconnected", true, true, true},
		{"host", "waiting", false, false, false},
	} {
		name := tc.role + "/" + tc.phase
		s := active.State{ID: "fixture", Device: "Test Host", Role: tc.role, Phase: tc.phase, Exchange: "fake.answer", Note: "fixture status"}
		body := v.status(s, nil)
		if strings.Contains(body, "/link") != tc.showLink || strings.Contains(body, "/receipt") != tc.showReceipt ||
			strings.Contains(body, "/revoke") != tc.showRevoke || !strings.Contains(body, "Test Host") || !strings.Contains(body, s.Note) {
			t.Fatalf("%s: unexpected actions or missing metadata: %q", name, body)
		}
		if tc.role == "host" {
			home := v.home("dev", 22, s, nil)
			if !strings.Contains(home, "被控面板") || !strings.Contains(home, "/status") || strings.Contains(home, "继续连接") {
				t.Fatalf("host home shows incorrect role actions: %q", home)
			}
		}
	}
	if bad := v.status(active.State{}, errors.New("fixture unavailable")); !strings.Contains(bad, "fixture unavailable") || strings.Contains(bad, "/link") {
		t.Fatalf("failed status hinted a connection: %q", bad)
	}
}

func TestShortNarrowHelpRetainsEveryCommand(t *testing.T) {
	v := newTerminalView(34, 14, false)
	body := v.help()
	for _, group := range helpGroups {
		for _, action := range group.actions {
			if strings.Count(body, action.command) != 1 {
				t.Fatalf("help without unique %s: %q", action.command, body)
			}
		}
	}
	if strings.Count(body, "\n") > 7 {
		t.Fatalf("short help exceeds expected row budget: %q", body)
	}
}

func TestTerminalHomeShowsSelectedControlAndNarrowHeightBudget(t *testing.T) {
	s := active.State{ID: "fixture", Role: "control", Phase: "waiting"}
	compact := newTerminalView(46, 14, false).home("dev", 22, s, nil)
	regular := newTerminalView(46, 20, false).home("dev", 22, s, nil)
	for _, log := range []string{compact, regular} {
		if !strings.Contains(log, "继续连接") || !strings.Contains(log, "/status") || strings.Contains(log, "创建邀请并核对回执") {
			t.Fatalf("active control home offered wrong roles: %q", log)
		}
	}
	if strings.Contains(compact, "再复制回执") || !strings.Contains(regular, "再复制回执") {
		t.Fatalf("waiting receipt hint misplaced: compact=%q tall=%q", compact, regular)
	}
}

func TestTerminalHelpPreservesCommandsAtWideAndTallSizes(t *testing.T) {
	for _, dims := range [][2]int{{93, 12}, {48, 32}, {22, 13}} {
		body := newTerminalView(dims[0], dims[1], false).help()
		for _, group := range helpGroups {
			for _, action := range group.actions {
				if strings.Count(body, action.command) != 1 {
					t.Fatalf("help dimensions %v did not retain each action once: %s / %q", dims, action.command, body)
				}
			}
		}
	}
}
