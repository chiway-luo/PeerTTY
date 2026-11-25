//go:build !windows

package console

import "os"

const terminalInputPath = "/dev/tty"

func nativeCookedLine(*os.File) *cookedLine { return nil }

func enableScreenOutput(*os.File) func() { return func() {} }
