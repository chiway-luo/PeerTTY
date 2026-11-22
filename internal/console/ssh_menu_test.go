package console

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"peertty/internal/localssh"
)

func sshMenuInput(t *testing.T, input string) (*os.File, *bytes.Buffer) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if _, err := f.WriteString(input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return f, &bytes.Buffer{}
}

func TestSSHMenuAdminRestartKeepsSettingsWithoutGrant(t *testing.T) {
	for _, ok := range []bool{true, false} {
		name := "restart succeeds"
		if !ok {
			name = "restart fails and can return"
		}
		t.Run(name, func(t *testing.T) {
			in, out := sshMenuInput(t, "1\n0\n")
			menu := Console{Settings: Settings{KeyPath: "identity", STUN: "none", TTL: time.Hour, SSHPort: 2222}, in: in, out: out}
			var captured []string
			inspect := func() localssh.Check {
				return localssh.Check{Message: "needs approval", Detail: "fixture detail", Action: "extra window",
					StartAdmin: func(args []string) error {
						captured = args
						if ok {
							return nil
						}
						return errors.New("declined fixture")
					}}
			}
			wantErr := errBack
			if ok {
				wantErr = errNewWindow
			}
			if err := menu.checkSSH(t.Context(), true, inspect); !errors.Is(err, wantErr) {
				t.Fatalf("result = %v, want %v", err, wantErr)
			}
			want := []string{"menu", "-key", "identity", "-stun", "none", "-ttl", "1h0m0s", "-ssh-port", "2222"}
			if !reflect.DeepEqual(captured, want) {
				t.Fatalf("restarted with %q, want %q", captured, want)
			}
			if !strings.Contains(out.String(), "fixture detail") || strings.Contains(out.String(), "declined fixture") == ok {
				t.Fatalf("unexpected transcript: %q", out.String())
			}
		})
	}
}

func TestSSHMenuPackageSelectionAndRetry(t *testing.T) {
	packagePath := filepath.Join(t.TempDir(), "example package.pkg")
	in, out := sshMenuInput(t, "1\n\n1\n\""+packagePath+"\"\n2\n")
	menu := Console{in: in, out: out}
	var applied []string
	attempts := 0
	inspect := func() localssh.Check {
		attempts++
		if attempts == 4 {
			return localssh.Check{Ready: true}
		}
		return localssh.Check{Action: "choose a package", PackageExt: ".pkg",
			Apply: func(_ context.Context, _ *os.File, _ io.Writer, path string) error {
				applied = append(applied, path)
				return errors.New("fixture apply failure")
			}}
	}
	if err := menu.checkSSH(t.Context(), true, inspect); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(applied, []string{packagePath}) || attempts != 4 || !strings.Contains(out.String(), "fixture apply failure") {
		t.Fatalf("attempts=%d applied=%q transcript=%q", attempts, applied, out.String())
	}
}

func TestSSHMenuDoesNotOfferHostOnlyOptionsInClientMode(t *testing.T) {
	in, out := sshMenuInput(t, "1\n3\nother\n0\n")
	menu := Console{in: in, out: out}
	if err := menu.checkSSH(t.Context(), false, func() localssh.Check { return localssh.Check{} }); !errors.Is(err, errBack) {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "修改本机 SSH 端口") || strings.Count(out.String(), "请选择屏幕列出的操作") != 3 {
		t.Fatalf("unexpected transcript: %q", out.String())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := menu.checkSSH(ctx, false, func() localssh.Check { t.Fatal("ran after cancel"); return localssh.Check{} }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
