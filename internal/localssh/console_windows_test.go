package localssh

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSSHDChildrenHaveNoConsoleWindow(t *testing.T) {
	const role = "PEERTTY_TEST_CONSOLE_ROLE"
	const run = "-test.run=^TestWindowsSSHDChildrenHaveNoConsoleWindow$"
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	switch os.Getenv(role) {
	case "child":
		window, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
		if window != 0 {
			t.Fatalf("child has a console window: %#x", window)
		}
	case "worker":
		for name, cmd := range map[string]*exec.Cmd{
			"guard":        guardCmd(exe, "0"),
			"login-open":   loginGuard(exe, "0", false),
			"login-closed": loginGuard(exe, "0", true),
			"native sshd":  backgroundCommand(t.Context(), exe, run),
		} {
			// Run the window probe with the production command's process attributes.
			cmd.Args = []string{exe, run}
			cmd.Env = append(os.Environ(), role+"=child")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s: %v\n%s", name, err, out)
			}
		}
	default:
		// Reproduce launching children from the detached grant worker, even
		// when the test runner itself has a console that they could inherit.
		cmd := exec.CommandContext(t.Context(), exe, run)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
		cmd.Env = append(os.Environ(), role+"=worker")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("worker: %v\n%s", err, out)
		}
	}
}
