package console

import (
	"fmt"
	"time"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
)

const spinFrames = "|/-\\"
const spinInterval = 200 * time.Millisecond
const waitForApprovalAndRoute = "等待被控方批准并建立直连"

func waitLabel(s active.State) string {
	switch s.Phase {
	case "gathering":
		return "正在收集直连地址"
	case "waiting":
		if s.Role == "host" {
			return "等待控制端回执"
		}
		return waitForApprovalAndRoute
	case "connecting":
		return "正在建立直连"
	case "disconnected":
		return reconnectNotice
	default:
		return ""
	}
}

func (t *Console) setActivity(label string) {
	t.setStatusRow(label, "")
}

func (t *Console) hasStatusRow() bool {
	return t.activity != "" || t.grantClock != ""
}

func grantClock(st active.State) string {
	if st.ID == "" || st.Deadline.IsZero() {
		return ""
	}
	return "剩余 " + st.TimeLeft().Round(time.Second).String()
}

func (t *Console) setStatusRow(activity, clock string) {
	if !t.fullScreen || (t.activity == activity && t.grantClock == clock) {
		return
	}
	hadRow := t.hasStatusRow()
	if t.activity != activity {
		t.frame = 0
	}
	t.activity, t.grantClock = activity, clock
	if activity == "" && clock == "" {
		fmt.Fprint(t.out, "\x1b7\x1b[r\x1b[H\x1b[2K\x1b8")
		return
	}
	// Reserve a row above the scroll region for long pastes. Only its first
	// allocation may reposition the cursor on the editing line.
	if !hadRow {
		fmt.Fprint(t.out, "\x1b[2;r\x1b[2;1H")
	}
	t.drawActivity()
}

func (t *Console) drawActivity() {
	v := t.view()
	line := t.grantClock
	if t.activity != "" {
		line = fmt.Sprintf("%c %s", spinFrames[t.frame], t.activity)
		if t.grantClock != "" && ansi.StringWidth(line+"  "+t.grantClock) <= v.width {
			line += "  " + t.grantClock
		}
	}
	t.writeTopRow(v, v.accent(line))
}

// Updating the reserved row in one write keeps the input and cursor intact.
func (t *Console) writeTopRow(v terminalView, text string) {
	fmt.Fprint(t.out, "\x1b7\x1b[H\x1b[2K", ansi.Truncate(text, v.width, ""), "\x1b8")
}

// Publish a grant change without moving a live Windows input line.
func (t *Console) showEditStatus(v terminalView, st active.State, err error, notice string) {
	if notice == "" && st.Phase == "disconnected" {
		notice = reconnectNotice
	}
	label := v.grantIndicator(st, err)
	if notice != "" {
		label = v.ink("33", "! "+notice)
	} else if err == nil && st.ID != "" {
		label += fmt.Sprintf("  已连终端 %d", st.Terminals)
		if clock := grantClock(st); clock != "" && ansi.StringWidth(label+"  "+clock) <= v.width {
			label += "  " + clock
		}
	}
	if t.editStatus != label && t.fullScreen && v.height > 1 {
		t.writeTopRow(v, label)
	}
	t.editStatus = label
}

func (t *Console) advanceActivity() {
	if t.activity != "" && t.editStatus == "" {
		t.frame = (t.frame + 1) % len(spinFrames)
		fmt.Fprintf(t.out, "\x1b7\x1b[H%c\x1b8", spinFrames[t.frame])
	}
}
