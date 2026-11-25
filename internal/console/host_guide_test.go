package console

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestHostGuideFitsTerminal(t *testing.T) {
	st := active.State{
		PairingCode: "11111111-22222222-33333333-44444444",
		Deadline:    time.Date(2026, 11, 25, 18, 30, 0, 0, time.Local),
		Exchange:    "/fixture/session.offer",
		Note:        strings.Repeat("fixture diagnostic ", 20),
	}
	for _, size := range [][2]int{{32, 14}, {36, 12}, {40, 12}, {46, 24}, {60, 18}, {80, 24}, {120, 30}} {
		for _, color := range []bool{true, false} {
			t.Run(fmt.Sprintf("%dx%d/color=%t", size[0], size[1], color), func(t *testing.T) {
				v := newTerminalView(size[0], size[1], color)
				body := "等待控制端回执\n" + v.heading("被控面板") + v.hostGuide(st, "已复制到系统剪贴板。")
				if !color && strings.Contains(body, "\x1b[0m") {
					t.Fatal("monochrome guide contains color")
				}
				visible := ansi.Strip(body)
				rows := strings.Split(visible, "\n")
				if len(rows) > size[1] {
					t.Fatalf("first step scrolls off screen: %d rows\n%s", len(rows), visible)
				}
				for _, row := range rows {
					for _, part := range strings.Split(row, "\r") {
						if ansi.StringWidth(part) >= size[0] {
							t.Fatalf("terminal would wrap %q", part)
						}
					}
				}
				// Very narrow windows can wrap a code between its groups.
				flat := strings.Join(strings.Fields(visible), "")
				rest := flat
				for _, want := range []string{"1.", "私发", "已复制", "2.", "一次性配对码", string(st.PairingCode), "授权有效至11-2518:30", "3.", "读取剪贴板回执", "回车"} {
					var ok bool
					if _, rest, ok = strings.Cut(rest, want); !ok {
						t.Fatalf("missing or misplaced %q\n%s", want, visible)
					}
				}
				if size[0] >= 36 && !strings.Contains(visible, string(st.PairingCode)) {
					t.Fatal("code wraps despite room for the entire value")
				}
				if strings.Contains(visible, st.Exchange) || strings.Contains(visible, "直连地址") || strings.Contains(visible, st.Note) {
					t.Fatal("diagnostics displaced pairing instructions")
				}
			})
		}
	}
}

func TestCompactHostApprovalKeepsIdentityAndScopeInView(t *testing.T) {
	v := newTerminalView(36, 12, false)
	offer := grant.Ticket{Claims: grant.Claims{SSHUser: "fixture"}}
	answer := grant.Ticket{Claims: grant.Claims{Issuer: make(ed25519.PublicKey, ed25519.PublicKeySize), DeviceName: "测试控制端"}}
	for _, scoped := range []bool{false, true} {
		var out bytes.Buffer
		if scoped {
			answer.Claims.SSHLoginKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
		}
		c := Console{out: &out}
		c.showCompactHostApproval(v, offer, answer)
		text := ansi.Strip("回执已核验 · 等待本机批准\n" + v.heading("被控面板") + out.String())
		if strings.Count(text, "\n")+1 > v.height {
			t.Fatal("approval panel scrolls past the device being approved")
		}
		wants := []string{answer.Claims.DeviceName, grant.ShortFingerprint(grant.Fingerprint(answer.Claims.Issuer)), "核对控制方回执页", "多终端", "关菜单仍有效", "[y] 批准", "[r] 重选", "[q] 撤销"}
		if scoped {
			wants = append(wants, "直接登录账号 fixture")
		} else {
			wants = append(wants, "系统 SSH 认证")
		}
		if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
			wants = append(wants, "已有的 sudo 规则")
		}
		for _, want := range wants {
			if !strings.Contains(text, want) {
				t.Fatalf("approval omitted %q", want)
			}
		}
	}
}

func TestHostGuideReportsClipboardOutcome(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, tc := range []struct {
		name, status, want string
		copyOn             bool
		copyErr            error
	}{
		{name: "disabled", want: "[c] 复制邀请"},
		{name: "copied", copyOn: true, status: "已复制到系统剪贴板。", want: "已复制到系统剪贴板。"},
		{name: "unconfirmed", copyOn: true, status: "已向终端发送复制请求，是否写入取决于终端的剪贴板设置。", want: "已向终端发送复制请求"},
		{name: "failed", copyOn: true, copyErr: errors.New("fixture clipboard unavailable"), want: "复制失败，可输入 v 查看邀请全文"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			copies := 0
			offer := grant.Ticket{Claims: grant.Claims{Session: "fixture invite"}}
			c := Console{out: &out, fullScreen: true, copyToClipboard: func(_ context.Context, dest io.Writer, value grant.Ticket) (string, error) {
				copies++
				if dest != &out || value.Claims.Session != offer.Claims.Session {
					t.Fatal("copier did not receive the active invite and terminal")
				}
				return tc.status, tc.copyErr
			}}
			st := active.State{Phase: "waiting", Role: "host", PairingCode: fixtureCode}
			c.showHostGuide(t.Context(), st, offer, tc.copyOn)
			shown := out.String()
			if !strings.Contains(shown, tc.want) || strings.Contains(shown, "已复制") != (tc.name == "copied") || strings.Contains(shown, ticketBegin) {
				t.Fatal("clipboard result or fallback is misleading")
			}
			out.Reset()
			c.hostInputPrompt(st, offer, nil)
			if (copies == 1) != tc.copyOn || copies > 1 || strings.Contains(out.String(), "已复制") {
				t.Fatal("redrawing the guide copied again or implied current clipboard contents")
			}
		})
	}
}
