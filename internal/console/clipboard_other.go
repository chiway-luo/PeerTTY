//go:build !windows

package console

func nativeWriteClipboard(string) (bool, error) { return false, nil }
func nativeReadClipboard() (string, bool, error) { return "", false, nil }
func windowsPowerShellPath() string             { return "" }
