//go:build windows

package console

import (
	"errors"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

var (
	user32DLL              = windows.NewLazySystemDLL("user32.dll")
	openClipboard          = user32DLL.NewProc("OpenClipboard")
	closeClipboard         = user32DLL.NewProc("CloseClipboard")
	emptyClipboard         = user32DLL.NewProc("EmptyClipboard")
	getClipboardData       = user32DLL.NewProc("GetClipboardData")
	setClipboardData       = user32DLL.NewProc("SetClipboardData")
	createClipboardWindow  = user32DLL.NewProc("CreateWindowExW")
	destroyClipboardWindow = user32DLL.NewProc("DestroyWindow")

	globalAlloc   = consoleDLL.NewProc("GlobalAlloc")
	globalLock    = consoleDLL.NewProc("GlobalLock")
	globalUnlock  = consoleDLL.NewProc("GlobalUnlock")
	globalFree    = consoleDLL.NewProc("GlobalFree")
	globalSize    = consoleDLL.NewProc("GlobalSize")
	rtlMoveMemory = consoleDLL.NewProc("RtlMoveMemory")
)

func openWinClipboard(owner uintptr) error {
	for range 5 {
		if ok, _, _ := openClipboard.Call(owner); ok != 0 {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("无法打开 Windows 剪贴板")
}

func nativeWriteClipboard(text string) (bool, error) {
	utf16, err := windows.UTF16FromString(text)
	if err != nil {
		return true, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// A message-only STATIC window owns the transaction even in Windows Terminal.
	class, _ := windows.UTF16PtrFromString("STATIC")
	const hwndMessage = ^uintptr(2)
	owner, _, err := createClipboardWindow.Call(0, uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 0, 0, hwndMessage, 0, 0, 0)
	if owner == 0 {
		return true, err
	}
	defer destroyClipboardWindow.Call(owner)
	bytesLen := uintptr(len(utf16) * 2)
	hMem, _, err := globalAlloc.Call(gmemMoveable, bytesLen)
	if hMem == 0 {
		return true, err
	}
	defer func() {
		if hMem != 0 {
			globalFree.Call(hMem)
		}
	}()
	ptr, _, err := globalLock.Call(hMem)
	if ptr == 0 {
		return true, err
	}
	rtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&utf16[0])), bytesLen)
	globalUnlock.Call(hMem)
	if err := openWinClipboard(owner); err != nil {
		return true, err
	}
	defer closeClipboard.Call()
	if ok, _, err := emptyClipboard.Call(); ok == 0 {
		return true, err
	}
	if res, _, err := setClipboardData.Call(cfUnicodeText, hMem); res == 0 {
		return true, err
	}
	hMem = 0 // SetClipboardData transferred ownership to the system.
	return true, nil
}

func nativeReadClipboard() (string, bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := openWinClipboard(0); err != nil {
		return "", true, err
	}
	defer closeClipboard.Call()
	hMem, _, err := getClipboardData.Call(cfUnicodeText)
	if hMem == 0 {
		return "", true, err
	}
	sizeBytes, _, _ := globalSize.Call(hMem)
	if sizeBytes > uintptr(maxPaste+1)*2 {
		return "", true, oversizePaste
	}
	ptr, _, err := globalLock.Call(hMem)
	if ptr == 0 {
		return "", true, err
	}
	defer globalUnlock.Call(hMem)
	maxUnits := int(sizeBytes / 2)
	if maxUnits == 0 {
		return "", true, nil
	}
	units := make([]uint16, maxUnits)
	rtlMoveMemory.Call(uintptr(unsafe.Pointer(&units[0])), ptr, uintptr(maxUnits*2))
	return windows.UTF16ToString(units), true, nil
}

func windowsPowerShellPath() string {
	if dir, err := windows.GetSystemDirectory(); err == nil {
		return filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	return "powershell.exe"
}
