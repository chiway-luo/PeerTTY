//go:build darwin || linux

package console

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPasteModeRequiresSameCharacterDeviceAndCapableTerminal(t *testing.T) {
	in, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	peer, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	other, err := os.Open("/dev/zero")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	file, _ := sshMenuInput(t, "fixture\n")
	closed, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TERM", "xterm")
	if got := pasteTerminal(in, peer); got != peer {
		t.Fatal("did not recognize the matched device")
	}
	for _, files := range [][2]*os.File{{file, file}, {closed, peer}, {in, closed}, {in, other}} {
		if got := pasteTerminal(files[0], files[1]); got != nil {
			t.Fatalf("enabled paste mode for mismatched or unusable files: %v", got)
		}
	}
	t.Setenv("TERM", "dumb")
	if pasteTerminal(in, peer) != nil {
		t.Fatal("enabled paste mode on a dumb terminal")
	}
}

func TestPromptOwnsPasteModeThroughOnePendingEntry(t *testing.T) {
	in, out := sshMenuInput(t, "Q\nnext\n")
	mode, err := os.CreateTemp(t.TempDir(), "modes")
	if err != nil {
		t.Fatal(err)
	}
	defer mode.Close()
	c := Console{in: in, out: out, pasteTTY: mode}
	ch := c.next()
	if c.next() != ch {
		t.Fatal("opened a second read before completing the first entry")
	}
	if got, err := c.prompt(t.Context(), "first: "); got != "" || !errors.Is(err, errBack) {
		t.Fatalf("back returned %q, %v", got, err)
	}
	c.finishEntry()
	if got, err := c.prompt(t.Context(), "second: "); got != "next" || err != nil || c.pending != nil {
		t.Fatalf("second prompt returned %q, %v", got, err)
	}
	codes, err := os.ReadFile(mode.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(codes) != strings.Repeat("\x1b[?2004h\x1b[?2004l", 2) {
		t.Fatalf("paste mode was not balanced: %q", codes)
	}
}
