//go:build !windows

package console

import "os"

func enableScreenOutput(*os.File) func() { return func() {} }
