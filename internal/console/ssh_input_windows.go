package console

import "os"

func keepSSHInput(*os.File) (func() error, error) { return func() error { return nil }, nil }
