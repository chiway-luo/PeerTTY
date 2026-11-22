//go:build !windows

package console

import "os"

const terminalInputPath = "/dev/tty"

func enableScreenOutput(*os.File) func() { return func() {} }
