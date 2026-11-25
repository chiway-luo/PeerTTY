package console

import (
	"os"
	"unsafe"

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

var readConsoleInput = consoleDLL.NewProc("ReadConsoleInputW")

func nativeCookedLine(in *os.File) *cookedLine {
	h := windows.Handle(in.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil || mode&windows.ENABLE_LINE_INPUT == 0 {
		return nil
	}
	return &cookedLine{owner: make(chan struct{}, 1), waitForKey: func() error {
		for {
			if _, err := windows.WaitForSingleObject(h, windows.INFINITE); err != nil {
				return err
			}
			var event inputRecord
			var count uint32
			ok, _, err := peekConsoleInput.Call(uintptr(h), uintptr(unsafe.Pointer(&event)), 1, uintptr(unsafe.Pointer(&count)))
			if ok == 0 {
				return err
			}
			if count == 0 {
				continue
			}
			// Preserve editing keys and Alt-numpad character completion. The
			// high-level reader ignores resize/focus events and ordinary
			// key releases (including Enter-up from the previous command).
			if event.startsLine() {
				return nil
			}
			if ok, _, err = readConsoleInput.Call(uintptr(h), uintptr(unsafe.Pointer(&event)), 1, uintptr(unsafe.Pointer(&count))); ok == 0 {
				return err
			}
		}
	}}
}

func (e inputRecord) startsLine() bool {
	if e.kind != windows.KEY_EVENT {
		return false
	}
	const vkAlt = 0x12
	if e.down == 0 {
		return e.key == vkAlt && e.char != 0
	}
	// A modifier alone does not start a line. Windows includes its state
	// on the subsequent key event, including for IME and pasted input.
	const vkShift, vkLeftShift, vkRightAlt = 0x10, 0xa0, 0xa5
	return e.char != 0 || !(vkShift <= e.key && e.key <= vkAlt || vkLeftShift <= e.key && e.key <= vkRightAlt)
}
