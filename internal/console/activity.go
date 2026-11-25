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

// Reserve the top row while waiting. Pasting a ticket can scroll many rows
// below it. Updating one cell leaves the current input and cursor intact.
func (t *Console) setActivity(label string) {
	if !t.fullScreen || t.activity == label {
		return
	}
	t.activity, t.frame = label, 0
	if label == "" {
		fmt.Fprint(t.out, "\x1b7\x1b[r\x1b[H\x1b[2K\x1b8")
		return
	}
	fmt.Fprint(t.out, "\x1b[2;r\x1b[2;1H")
	t.drawActivity()
}

func (t *Console) drawActivity() {
	v := t.view()
	line := fmt.Sprintf("%c %s", spinFrames[t.frame], t.activity)
	fmt.Fprint(t.out, "\x1b7\x1b[H\x1b[2K", v.accent(ansi.Truncate(line, v.width, "")), "\x1b8")
}

func (t *Console) advanceActivity() {
	if t.activity != "" {
		t.frame = (t.frame + 1) % len(spinFrames)
		fmt.Fprintf(t.out, "\x1b7\x1b[H%c\x1b8", spinFrames[t.frame])
	}
}
