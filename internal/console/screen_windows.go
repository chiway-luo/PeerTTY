package console

import (
	"os"

	"golang.org/x/sys/windows"
)

func enableScreenOutput(out *os.File) func() {
	handle := windows.Handle(out.Fd())
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		return nil
	}
	vt := mode | windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if vt == mode {
		return func() {}
	}
	if windows.SetConsoleMode(handle, vt) != nil {
		return nil
	}
	return func() { windows.SetConsoleMode(handle, mode) }
}
