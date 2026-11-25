package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"peertty/internal/grant"
)

// Windows echoes a cooked line itself, but cannot repaint it after an
// application erases the screen. Wait for the first key before taking the
// lock so idle prompts can refresh. Once typing begins, keep the console's
// native editing, IME and paste behavior until this entry is submitted.
type cookedLine struct {
	owner      chan struct{}
	waitForKey func() error
}

func (e *cookedLine) read(in io.Reader) (string, error) {
	if e != nil {
		if err := e.waitForKey(); err != nil {
			return "", err
		}
		e.owner <- struct{}{}
		defer e.unlock()
	}
	return readEntry(in)
}

func (e *cookedLine) tryLock() bool {
	if e == nil {
		return true
	}
	select {
	case e.owner <- struct{}{}:
		return true
	default:
		return false
	}
}

func (e *cookedLine) unlock() {
	if e != nil {
		<-e.owner
	}
}

type line struct {
	text string
	err  error
}

const (
	pasteStart = "\x1b[200~"
	pasteEnd   = "\x1b[201~"
	maxPaste   = 2 * grant.MaxTicketSize
)

type inputIssue string

func (e inputIssue) Error() string { return string(e) }

const (
	incompletePaste inputIssue = "粘贴内容不完整，请重新复制从 BEGIN 到 END 的完整文本。"
	oversizePaste   inputIssue = "粘贴内容超过长度限制，请只复制一份邀请或回执。"
)

// At most one read can be pending after a grant expires. The next menu prompt
// reuses that read. Reading just one entry leaves SSH's stdin and tty intact.
func (t *Console) next() <-chan line {
	if t.pending == nil {
		if t.lineEdit != nil && t.fullScreen && !t.hasStatusRow() {
			// Keep the first row available for changes to the grant while the
			// native editor owns the rest of the screen, even for a long paste.
			fmt.Fprint(t.out, "\x1b7\x1b[2;r\x1b8")
		}
		if t.pasteTTY != nil {
			io.WriteString(t.pasteTTY, "\x1b[?2004h")
		}
		ch := make(chan line, 1)
		t.pending = ch
		go func() { text, err := t.lineEdit.read(t.in); ch <- line{text, err} }()
	}
	return t.pending
}

// Request bracketed paste only while the menu owns a real interactive terminal.
// SSH and native authentication prompts receive its normal input mode.
func pasteTerminal(in *os.File, out io.Writer) *os.File {
	f, ok := out.(*os.File)
	if !ok || runtime.GOOS == "windows" || os.Getenv("TERM") == "dumb" {
		return nil
	}
	src, err := in.Stat()
	if err != nil || src.Mode()&os.ModeCharDevice == 0 {
		return nil
	}
	dst, err := f.Stat()
	if err != nil || !os.SameFile(src, dst) {
		return nil
	}
	return f
}

func (t *Console) finishEntry() {
	if t.pending != nil && t.lineEdit != nil && t.fullScreen && !t.hasStatusRow() {
		fmt.Fprint(t.out, "\x1b7\x1b[r\x1b8")
	}
	if t.pending != nil && t.pasteTTY != nil {
		io.WriteString(t.pasteTTY, "\x1b[?2004l")
	}
	t.pending = nil
}

// The next prompt or result owns the entire page, including the space used
// by the terminal's echo of a multiline invitation.
func (t *Console) submitEntry() {
	t.finishEntry()
	t.clearPage()
}

func readLine(in io.Reader) (string, error) {
	// Stay in the terminal's regular line mode. A bracketed paste is one entry
	// even when it contains newlines. Leave everything after Enter for the next
	// prompt or the native SSH process.
	var data []byte
	var one [1]byte
	framed, closed, overflow := false, false, false
	matched := 0
	for {
		n, err := in.Read(one[:])
		if n > 0 {
			c := one[0]
			if c == '\n' && (!framed || closed) {
				break
			}
			if len(data) < maxPaste+len(pasteStart)+len(pasteEnd) {
				data = append(data, c)
			} else {
				overflow = true
			}
			if !framed && len(data) == len(pasteStart) {
				framed = string(data) == pasteStart
			} else if framed && !closed {
				if c == pasteEnd[matched] {
					matched++
					closed = matched == len(pasteEnd)
				} else {
					matched = 0
					if c == pasteEnd[0] {
						matched = 1
					}
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(data) > 0 {
				break
			}
			return "", err
		}
	}
	if overflow || (!framed && len(data) > grant.MaxTicketSize) {
		return "", oversizePaste
	}
	if framed {
		value, tail, ok := strings.Cut(string(data[len(pasteStart):]), pasteEnd)
		if !ok || strings.TrimSpace(tail) != "" {
			return "", incompletePaste
		}
		return pastedValue(value)
	}
	return strings.TrimSpace(string(data)), nil
}

func (t *Console) ask(ctx context.Context, prompt string) (string, error) {
	for {
		fmt.Fprint(t.pageOut(), prompt)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case value := <-t.next():
			t.submitEntry()
			if _, ok := value.err.(inputIssue); ok {
				t.notice("33", "!", value.err.Error())
				continue
			}
			return value.text, value.err
		}
	}
}

func (t *Console) prompt(ctx context.Context, prompt string) (string, error) {
	if t.terminalUI() {
		prompt = t.view().fieldPrompt(prompt, "q 返回主菜单")
	}
	v, err := t.ask(ctx, prompt)
	if err == nil && (v == "q" || v == "Q") {
		return "", errBack
	}
	return v, err
}
