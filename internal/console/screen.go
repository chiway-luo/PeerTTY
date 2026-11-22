package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"

	"peertty/internal/active"
)

const (
	enterScreen = "\x1b[?1049h"
	leaveScreen = "\x1b[?1049l"
	erasePage   = "\x1b[H\x1b[2J"
)

func (t *Console) openScreen() func() {
	if !t.interactive || os.Getenv("TERM") == "dumb" {
		return func() {}
	}
	restore := enableScreenOutput(t.out.(*os.File))
	if restore == nil {
		return func() {}
	}
	t.fullScreen = true
	fmt.Fprint(t.out, enterScreen)
	return func() {
		fmt.Fprint(t.out, leaveScreen)
		t.fullScreen = false
		restore()
	}
}

func (t *Console) clearPage() {
	if t.fullScreen {
		fmt.Fprint(t.out, erasePage)
		t.headingDrawn = false
	}
}

// Emit a section heading only when the new page actually produces content.
// Return the original writer so clipboard and native terminal detection still work.
func (t *Console) pageOut() io.Writer {
	if t.fullScreen && t.section != "" && !t.headingDrawn {
		fmt.Fprint(t.out, t.view().heading(t.section))
		t.headingDrawn = true
	}
	return t.out
}

func (t *Console) notice(color, mark, text string) {
	if t.fullScreen {
		v := t.view()
		fmt.Fprintln(t.pageOut(), v.margin+v.ink(color, mark)+" "+text)
	} else {
		fmt.Fprintln(t.out, text)
	}
}

func (t *Console) line(parts ...any) {
	out := t.pageOut()
	if t.fullScreen {
		fmt.Fprint(out, t.view().margin)
	}
	fmt.Fprintln(out, parts...)
}

// Give OpenSSH the regular terminal so remote full-screen programs can switch
// buffers themselves. Re-enter the menu even when the child exits with an error.
func (t *Console) nativeSSH(run func() error) error {
	if t.fullScreen {
		fmt.Fprint(t.out, leaveScreen, erasePage)
		defer fmt.Fprint(t.out, enterScreen, erasePage)
	}
	return run()
}

type menuPage int

const (
	homePage menuPage = iota
	statusPage
	helpPage
	resultPage
)

func (t *Console) drawMenu(v terminalView, page menuPage, s active.State, err error) {
	t.clearPage()
	if page == helpPage {
		if t.fullScreen {
			fmt.Fprint(t.pageOut(), v.help())
		} else {
			fmt.Fprintln(t.out, "全部操作")
			for _, group := range helpGroups {
				for _, a := range group.actions {
					fmt.Fprintf(t.out, "  %-11s %1s  %s\n", a.command, a.key, a.title)
				}
			}
		}
		return
	}
	if page == homePage {
		t.section = ""
	}
	if t.fullScreen {
		if page == homePage {
			fmt.Fprint(t.out, v.home(t.Version, t.SSHPort, s, err))
		} else {
			fmt.Fprint(t.pageOut(), v.status(s, err))
		}
		return
	}
	if page == homePage {
		fmt.Fprintln(t.out, "PeerTTY · 点对点远程终端")
		fmt.Fprintln(t.out, "1 /connect 控制设备    2 /host 允许被控制    /help 全部操作")
		fmt.Fprintln(t.out, "可直接粘贴邀请，/paste 读取剪贴板，/status 查看授权。")
	}
	if err != nil {
		if page == statusPage {
			fmt.Fprintln(t.out, err)
		}
		return
	}
	printStatus(t.out, s)
	if page == statusPage && s.Phase == "disconnected" {
		fmt.Fprintln(t.out, "/revoke 立即结束授权")
	}
	if page == homePage {
		if s.Role == "host" {
			fmt.Fprintln(t.out, "/host 查看活动和邀请，/revoke 撤销。")
		} else {
			fmt.Fprintln(t.out, "/link 打开终端，/revoke 结束授权。")
		}
	}
}

// Only the home and status pages follow the grant while waiting for a command.
// Reuse the pending read so a refresh or an expired grant cannot consume input.
func (t *Console) menuChoice(ctx context.Context, page menuPage) (string, error) {
	v := t.view()
	if page == resultPage {
		if t.fullScreen {
			return t.ask(ctx, v.commandPrompt(false, false))
		}
		return t.ask(ctx, "❯ ")
	}
	var last active.State
	var statusErr error
	if page != helpPage {
		last, statusErr = active.Status(ctx, t.KeyPath)
	}
	t.drawMenu(v, page, last, statusErr)
	if !t.fullScreen {
		return t.ask(ctx, "❯ ")
	}
	prompt := v.commandPrompt(page == homePage, last.ID != "")
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	fmt.Fprint(t.out, prompt)
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case item := <-t.next():
			t.submitEntry()
			if _, ok := item.err.(inputIssue); ok {
				t.drawMenu(v, page, last, statusErr)
				t.notice("33", "!", item.err.Error())
				fmt.Fprint(t.out, prompt)
				continue
			}
			return item.text, item.err
		case <-tick.C:
			nextView := t.view()
			s, err := last, statusErr
			if page != helpPage {
				s, err = active.Status(ctx, t.KeyPath)
				if err != nil && !errors.Is(err, active.ErrInactive) {
					s, err = last, statusErr
				}
			}
			if nextView != v || s != last || (statusErr == nil) != (err == nil) {
				v = nextView
				prompt = v.commandPrompt(page == homePage, s.ID != "")
				t.drawMenu(v, page, s, err)
				if page == homePage && last.ID != "" && errors.Is(err, active.ErrInactive) {
					fmt.Fprintln(t.out, "授权已结束。")
				}
				fmt.Fprint(t.out, prompt)
				last, statusErr = s, err
			}
		}
	}
}

func terminalFile(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
