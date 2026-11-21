package console

import (
	"os"
	"strings"
)

// The compact mark uses the two prompts from assets/peertty-icon.png.
func (v terminalView) compactMark() string {
	return v.accent("❯") + v.bold("_")
}

// Use the icon's mint and graphite for filled controls. Ordinary text retains
// the terminal theme's foreground for contrast on both light and dark screens.
func brandColors() (edge, fill string) {
	switch strings.ToLower(os.Getenv("COLORTERM")) {
	case "truecolor", "24bit":
		return "38;2;92;243;198", "1;38;2;15;15;16;48;2;92;243;198"
	}
	if strings.Contains(os.Getenv("TERM"), "256color") {
		return "38;5;86", "1;38;5;16;48;5;86"
	}
	return "96", "1;30;106"
}

// Keep the corners of the offset panes on terminal cell boundaries.
func (v terminalView) brandIcon() [5]string {
	edge, fill := brandColors()
	top, front, bottom := "▗▄▄▄▄", "█  ❯  █", "▝▀▀▀▀▀▘"
	if v.color {
		top = v.ink(edge, "▗") + v.ink(fill, "    ")
		front = v.ink(fill, "   ❯   ")
		bottom = v.ink(edge, "▝") + v.ink(fill, "     ") + v.ink(edge, "▘")
	}
	return [5]string{
		"     " + v.bold("┏━━━━━┓"),
		"     " + v.bold("┃  ━━ ┃"),
		top + v.bold("┗━┓   ┃"),
		front + v.bold("┗━━━┛"),
		bottom,
	}
}
