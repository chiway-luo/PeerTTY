package console

import (
	"os"

	"github.com/mattn/go-isatty"
	"golang.org/x/sys/windows"
)

const terminalInputPath = "CONIN$"

func enableScreenOutput(out *os.File) func() {
	handle := windows.Handle(out.Fd())
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		if isatty.IsCygwinTerminal(out.Fd()) {
			return func() {}
		}
		return nil
	}
	vt := (mode | windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) &^ windows.DISABLE_NEWLINE_AUTO_RETURN
	if vt == mode {
		return func() {}
	}
	if windows.SetConsoleMode(handle, vt) != nil {
		return nil
	}
	return func() { windows.SetConsoleMode(handle, mode) }
}
