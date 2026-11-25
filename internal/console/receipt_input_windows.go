package console

import (
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	consoleDLL       = windows.NewLazySystemDLL("kernel32.dll")
	peekConsoleInput = consoleDLL.NewProc("PeekConsoleInputW")
	peekNamedPipe    = consoleDLL.NewProc("PeekNamedPipe")
)

type inputRecord struct {
	kind, padding           uint16
	down                    int32
	repeat, key, scan, char uint16
	control                 uint32
}

func (k *receiptKeys) poll(in *os.File) (string, bool, error) {
	h := windows.Handle(in.Fd())
	kind, err := windows.GetFileType(h)
	if err != nil {
		return "", false, err
	}
	if kind != windows.FILE_TYPE_CHAR {
		return k.readAvailable(in, func() (bool, error) {
			if kind == windows.FILE_TYPE_DISK {
				return true, nil
			}
			var available uint32
			ok, _, err := peekNamedPipe.Call(uintptr(h), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
			if ok == 0 {
				if err == windows.ERROR_BROKEN_PIPE {
					return false, io.EOF
				}
				return false, err
			}
			return available > 0, nil
		})
	}
	// Console handles also signal on resize, focus, and individual keystrokes.
	// Start a cooked line read only when a submitted line is in the queue.
	var count uint32
	if err := windows.GetNumberOfConsoleInputEvents(h, &count); err != nil || count == 0 {
		return "", false, err
	}
	events := make([]inputRecord, count)
	ok, _, err := peekConsoleInput.Call(uintptr(h), uintptr(unsafe.Pointer(&events[0])), uintptr(count), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return "", false, err
	}
	for _, e := range events[:count] {
		if e.kind == windows.KEY_EVENT && e.down != 0 && e.char == '\r' {
			value, err := readLine(in)
			return value, true, err
		}
	}
	return "", false, nil
}
