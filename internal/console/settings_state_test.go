package console

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"peertty/internal/active"
	"strings"
	"testing"
	"time"
)

func TestSettingsCommitBothFieldsOrNeither(t *testing.T) {
	const initial = "stun:old.example:3478"
	for _, tc := range []struct {
		name, input, stun string
		port              int
		err               error
		invalid           bool
	}{
		{"keep both", "\n\n", initial, 2222, nil, false},
		{"disable and retry port", "-\n65536\n65535\n", "", 65535, nil, false},
		{"cancel second prompt", "none\nq\n", initial, 2222, errBack, false},
		{"EOF at second prompt", "auto\n", initial, 2222, io.EOF, false},
		{"invalid server", "https://invalid.example\n", initial, 2222, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := os.CreateTemp(t.TempDir(), "input")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := io.WriteString(r, tc.input); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			c := Console{Settings: Settings{STUN: initial, SSHPort: 2222}, in: r, out: &out}
			err = c.settings(t.Context())
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid server accepted")
				}
			} else if !errors.Is(err, tc.err) {
				t.Fatalf("error = %v, want %v", err, tc.err)
			}
			if c.STUN != tc.stun || c.SSHPort != tc.port {
				t.Fatalf("settings = (%q,%d), want (%q,%d)", c.STUN, c.SSHPort, tc.stun, tc.port)
			}
			if strings.Contains(out.String(), "连接设置已应用") != (err == nil) {
				t.Fatal("unexpected acknowledgement:", out.String())
			}
		})
	}
}

func TestStatusTranscriptReportsExpiredGrantAndFiltersDeviceName(t *testing.T) {
	s := active.State{Role: "control", Phase: "offline", Terminals: 2, Deadline: time.Date(2001, 2, 3, 4, 5, 0, 0, time.Local), Device: "lab-box", Note: "fixture note"}
	for _, device := range []string{"lab-box", "bad\nname"} {
		s.Device = device
		var out bytes.Buffer
		printStatus(&out, s)
		for _, want := range []string{"控制端", "直连已中断", "2 个终端", "02-03 04:05", "剩余 0s", "fixture note"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("missing %q: %q", want, out.String())
			}
		}
		if strings.Contains(out.String(), device) != (device == "lab-box") {
			t.Fatalf("unexpected device rendering: %q", out.String())
		}
	}
}

func TestHandoffFailedCommandReleasesOffer(t *testing.T) {
	h := handoff{Offer: filepath.Join(t.TempDir(), "offer")}
	if err := os.WriteFile(h.Offer, []byte("offer"), 0600); err != nil {
		t.Fatal(err)
	}
	// A missing executable fails before any SSH or helper process is launched.
	if err := h.runSSH(exec.Command(filepath.Join(filepath.Dir(h.Offer), "missing-program"))); err == nil {
		t.Fatal("launch failure lost")
	}
	for _, path := range []string{h.Offer, h.workerPath()} {
		if busy, err := held(path); err != nil || busy {
			t.Errorf("lease %q survived failed launch: busy=%v err=%v", path, busy, err)
		}
	}
}
