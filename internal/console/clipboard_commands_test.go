package console

import (
	"os/exec"
	"slices"
	"testing"
)

func TestLinuxClipboardToolSelection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wayland   bool
		x11       bool
		write     bool
		installed []string
		searched  []string
		args      []string
	}{
		{"wayland read preferred", true, true, false, []string{"wl-paste", "xclip"}, []string{"wl-paste"}, []string{"/fixture/wl-paste", "--no-newline"}},
		{"wayland write preferred", true, true, true, []string{"wl-copy", "xclip"}, []string{"wl-copy"}, []string{"/fixture/wl-copy"}},
		{"fallback to xclip read", true, true, false, []string{"xclip"}, []string{"wl-paste", "xclip"}, []string{"/fixture/xclip", "-selection", "clipboard", "-out"}},
		{"xclip write", false, true, true, []string{"xclip", "xsel"}, []string{"xclip"}, []string{"/fixture/xclip", "-selection", "clipboard", "-in"}},
		{"xsel read", false, true, false, []string{"xsel"}, []string{"xclip", "xsel"}, []string{"/fixture/xsel", "--clipboard", "--output"}},
		{"xsel write", true, true, true, []string{"xsel"}, []string{"wl-copy", "xclip", "xsel"}, []string{"/fixture/xsel", "--clipboard", "--input"}},
		{"display with no helpers", true, true, true, nil, []string{"wl-copy", "xclip", "xsel"}, nil},
		{"headless", false, false, true, []string{"wl-copy", "xclip", "xsel"}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var searched []string
			cmd, err := clipboardCommandFor(t.Context(), tc.write, "linux", func(k string) string {
				if (k == "WAYLAND_DISPLAY" && tc.wayland) || (k == "DISPLAY" && tc.x11) {
					return "fixture display"
				}
				return ""
			}, func(exe string) (string, error) {
				searched = append(searched, exe)
				if slices.Contains(tc.installed, exe) {
					return "/fixture/" + exe, nil
				}
				return "", exec.ErrNotFound
			})
			if !slices.Equal(searched, tc.searched) {
				t.Fatalf("searched %v; want %v", searched, tc.searched)
			}
			if tc.args == nil {
				if cmd != nil || err == nil {
					t.Fatalf("unavailable clipboard resolved: %v, %v", cmd, err)
				}
			} else if err != nil || cmd == nil || !slices.Equal(cmd.Args, tc.args) {
				t.Fatalf("clipboard command = %v, %v; want %v", cmd, err, tc.args)
			}
		})
	}
}

func TestWindowsClipboardUsesFixedCommandsWithoutX11(t *testing.T) {
	for _, tc := range []struct {
		write  bool
		script string
	}{
		{false, "[Console]::Write((Get-Clipboard -Raw -ErrorAction Stop))"},
		{true, "Set-Clipboard -Value ([Console]::In.ReadToEnd()) -ErrorAction Stop"},
	} {
		cmd, err := clipboardCommandFor(t.Context(), tc.write, "windows", func(string) string {
			t.Fatal("Windows clipboard consulted display environment")
			return ""
		}, func(string) (string, error) {
			t.Fatal("Windows clipboard selected a Linux helper")
			return "", exec.ErrNotFound
		})
		if err != nil || cmd == nil || len(cmd.Args) < 2 ||
			!slices.Equal(cmd.Args[1:], []string{"-NoProfile", "-NonInteractive", "-STA", "-Command", tc.script}) {
			t.Fatalf("unexpected command (write=%v): %v, %v", tc.write, cmd, err)
		}
	}
	if cmd, err := clipboardCommandFor(t.Context(), false, "unknown", nil, nil); cmd != nil || err == nil {
		t.Fatalf("unsupported clipboard platform resolved a command: %v, %v", cmd, err)
	}
}
