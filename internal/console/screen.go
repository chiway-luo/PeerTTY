package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mattn/go-isatty"
	"golang.org/x/term"

	"peertty/internal/active"
)

const (
	enterScreen = "\x1b[?1049h"
	leaveScreen = "\x1b[?1049l"
	erasePage   = "\x1b[H\x1b[2J"
)

func (t *Console) openScreen() func() {
	out, ok := t.out.(*os.File)
	if !t.interactive || !ok || os.Getenv("TERM") == "dumb" {
		return func() {}
	}
	restore := enableScreenOutput(out)
	if restore == nil {
		return func() {}
	}
	t.fullScreen = true
	if t.in != nil {
		t.lineEdit = nativeCookedLine(t.in)
	}
	fmt.Fprint(t.out, enterScreen)
	return func() {
		fmt.Fprint(t.out, leaveScreen)
		t.fullScreen = false
		restore()
	}
}

func (t *Console) terminalUI() bool { return t.interactive || t.fullScreen }

func (t *Console) clearPage() {
	t.headingDrawn = false
	t.editStatus = ""
	if t.fullScreen {
		fmt.Fprint(t.out, erasePage)
		if t.activity != "" {
			t.drawActivity()
			fmt.Fprint(t.out, "\x1b[2;1H")
		}
	}
}

// Emit a section heading only when the new page actually produces content.
// Return the original writer so clipboard and native terminal detection still work.
func (t *Console) pageOut() io.Writer {
	if t.section != "" && !t.headingDrawn {
		fmt.Fprint(t.out, t.view().heading(t.section))
		t.headingDrawn = true
	}
	return t.out
}

func (t *Console) notice(color, mark, text string) {
	if t.terminalUI() {
		v := t.view()
		fmt.Fprintln(t.pageOut(), v.margin+v.ink(color, mark)+" "+text)
	} else {
		fmt.Fprintln(t.out, text)
	}
}

func (t *Console) line(parts ...any) {
	out := t.pageOut()
	if t.terminalUI() {
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
	if page == homePage {
		t.section = ""
	}
	t.clearPage()
	switch page {
	case homePage:
		fmt.Fprint(t.out, v.home(t.Version, t.SSHPort, s, err))
	case statusPage:
		fmt.Fprint(t.pageOut(), v.status(s, err))
	case helpPage:
		fmt.Fprint(t.pageOut(), v.help())
	}
}

// Only the home and status pages follow the grant while waiting for a command.
// Reuse the pending read so a refresh or an expired grant cannot consume input.
func (t *Console) menuChoice(ctx context.Context, page menuPage) (string, error) {
	return t.menuChoiceWith(ctx, page, active.Status)
}

func (t *Console) menuChoiceWith(ctx context.Context, page menuPage, status func(context.Context, string) (active.State, error)) (string, error) {
	v := t.view()
	if page == resultPage {
		return t.ask(ctx, v.commandPrompt(false, false))
	}
	var last active.State
	var statusErr error
	if page != helpPage {
		last, statusErr = status(ctx, t.KeyPath)
	}
	t.setActivity(waitLabel(last))
	defer t.setActivity("")
	t.drawMenu(v, page, last, statusErr)
	prompt := v.commandPrompt(page == homePage, last.ID != "")
	if !t.terminalUI() {
		return t.ask(ctx, prompt)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	frames := time.NewTicker(spinInterval)
	defer frames.Stop()
	fmt.Fprint(t.out, prompt)
	var ended string
	for {
		var animation <-chan time.Time
		if t.activity != "" && t.editStatus == "" {
			animation = frames.C
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-animation:
			t.advanceActivity()
		case item := <-t.next():
			t.submitEntry()
			if _, ok := item.err.(inputIssue); ok {
				v = t.view()
				t.setActivity(waitLabel(last))
				t.drawMenu(v, page, last, statusErr)
				prompt = v.commandPrompt(page == homePage, last.ID != "")
				t.notice("33", "!", item.err.Error())
				fmt.Fprint(t.out, prompt)
				continue
			}
			return item.text, item.err
		case <-tick.C:
			nextView := t.view()
			s, err := last, statusErr
			if page != helpPage {
				s, err = status(ctx, t.KeyPath)
				if err != nil && !errors.Is(err, active.ErrInactive) {
					s, err = last, statusErr
				}
			}
			changed := s != last
			if page == homePage {
				// The home header shows the role and phase. Each IPC poll also
				// returns a new Remaining pointer that does not change this page.
				changed = s.ID != last.ID || s.Role != last.Role || s.Phase != last.Phase
			}
			changed = changed || (statusErr == nil) != (err == nil)
			if last.ID != "" && errors.Is(err, active.ErrInactive) {
				ended = "授权已结束。"
				if last.Phase == "disconnected" || last.Phase == "offline" {
					ended = "直连已断开，本次授权已结束。请双方重新配对。"
				}
			} else if s.ID != "" {
				ended = ""
			}
			last, statusErr = s, err
			if nextView == v && !changed && t.editStatus == "" {
				continue
			}
			if !t.lineEdit.tryLock() {
				if changed {
					t.showEditStatus(nextView, s, err, ended)
				}
				continue
			}
			v = nextView
			prompt = v.commandPrompt(page == homePage, s.ID != "")
			t.setActivity(waitLabel(s))
			t.drawMenu(v, page, s, err)
			if ended != "" {
				t.notice("33", "!", ended)
			}
			fmt.Fprint(t.out, prompt)
			t.lineEdit.unlock()
		}
	}
}

func terminalFile(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && f != nil && (term.IsTerminal(int(f.Fd())) || isatty.IsCygwinTerminal(f.Fd()))
}
