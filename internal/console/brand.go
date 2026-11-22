package console

import (
	"os"
	"strings"
)

// Two offset square blocks keep the window motif in single-line headings.
func (v terminalView) compactMark() string {
	return v.accent("▄") + v.bold("▀")
}

func terminalPalette() int {
	switch strings.ToLower(os.Getenv("COLORTERM")) {
	case "truecolor", "24bit":
		return 1 << 24
	}
	if os.Getenv("WT_SESSION") != "" {
		return 1 << 24
	}
	if strings.Contains(os.Getenv("TERM"), "256color") {
		return 256
	}
	return 16
}

func brandFill() string {
	switch terminalPalette() {
	case 16:
		return "1;30;106"
	case 256:
		return "1;38;5;16;48;5;86"
	default:
		return "1;38;2;15;15;16;48;2;92;243;198"
	}
}

// Each block half is one square pixel. The left window is in front of the
// outlined window. Its arrow and every empty cell show the terminal background.
var terminalWindows = [...]struct{ front, rear string }{
	{"", "      █▀▀▀▀▀▀▀▀█"},
	{"", "      █        █"},
	{"", "      █  ▀▀▀▀  █"},
	{"███▀▀████", "      █"},
	{"████▄ ▀██", "▀▀▀▀▀▀▀"},
	{"███▀ ▄███", ""},
	{"█████████", ""},
}

func (v terminalView) brandIcon() []string {
	if v.width < 38 || v.height < 21 {
		return nil
	}
	rows := make([]string, len(terminalWindows))
	for i, line := range terminalWindows {
		// Both inks follow the terminal theme, including light and monochrome
		// palettes. Apply colour only to the filled pixels of the front pane.
		rows[i] = padCells(v.ink("36", line.front)+line.rear, 16)
	}
	return rows
}
