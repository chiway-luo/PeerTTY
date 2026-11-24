//go:build darwin || linux

package localssh

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSystemInstallAdviceValidatesLocalLinuxPackageBeforeDelegating(t *testing.T) {
	const apt, dnf, yum = "/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/yum"
	for _, tc := range []struct{ manager, ext, query string }{
		{apt, ".deb", "/usr/bin/dpkg-deb"},
		{dnf, ".rpm", "/usr/bin/rpm"},
		{yum, ".rpm", "/usr/bin/rpm"},
		{},
	} {
		t.Run(tc.manager, func(t *testing.T) {
			ctx := t.Context()
			path := filepath.Join(t.TempDir(), "fixture"+tc.ext)
			var checked []string
			look := func(name string) (string, error) {
				checked = append(checked, name)
				if name == tc.manager {
					return name, nil
				}
				return "", os.ErrNotExist
			}
			body, queryErr := []byte("not-peertty\n"), error(nil)
			queries, applied := 0, 0
			complete := errors.New("fixture package manager result")
			query := func(c context.Context, bin string, args ...string) ([]byte, error) {
				queries++
				want := []string{"-f", path, "Package"}
				if tc.ext == ".rpm" {
					want = []string{"-qp", "--queryformat", "%{NAME}", path}
				}
				if bin != tc.query || !slices.Equal(args, want) || c != ctx {
					t.Fatalf("wrong query %q %v", bin, args)
				}
				return body, queryErr
			}
			install := func(message, label, bin string, args ...string) Check {
				if bin != tc.manager || !slices.Equal(args, []string{"install", path}) || message != "" || label != "" {
					t.Fatalf("wrong package action %q %v", bin, args)
				}
				return Check{Apply: func(c context.Context, in *os.File, out io.Writer, extra string) error {
					applied++
					if c != ctx || in != nil || out != io.Discard || extra != "" {
						t.Fatal("changed install invocation")
					}
					return complete
				}}
			}
			c := systemInstallRequiredWith("linux", look, query, install, nil)
			if tc.manager == "" {
				if c.Apply != nil || c.Detail == "" || !slices.Equal(checked, []string{apt, dnf, yum}) || queries != 0 {
					t.Fatalf("no package manager should produce guidance only: %+v, %v", c, checked)
				}
				return
			}
			if c.Apply == nil || c.PackageExt != tc.ext || applied != 0 || queries != 0 {
				t.Fatalf("check didn't return deferred action: %+v", c)
			}
			for _, invalid := range []string{"relative" + tc.ext, filepath.Join(filepath.Dir(path), "wrong.txt")} {
				if err := c.Apply(ctx, nil, io.Discard, invalid); err == nil || queries != 0 || applied != 0 {
					t.Fatalf("invalid path caused query or install: %q, %v", invalid, err)
				}
			}
			if err := c.Apply(ctx, nil, io.Discard, path); err == nil || queries != 1 || applied != 0 {
				t.Fatalf("unrelated package was not rejected: %v", err)
			}
			body, queryErr = []byte("peertty\n"), os.ErrPermission
			if err := c.Apply(ctx, nil, io.Discard, path); err == nil || queries != 2 || applied != 0 {
				t.Fatalf("unreadable package was not rejected: %v", err)
			}
			queryErr = nil
			if err := c.Apply(ctx, nil, io.Discard, path); !errors.Is(err, complete) || queries != 3 || applied != 1 {
				t.Fatalf("valid package did not notify caller of installer result: %v, queries=%d applied=%d", err, queries, applied)
			}
		})
	}
}

func TestSystemInstallAdviceMacChooserDoesNotLaunchInvalidSelections(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "PeerTTY.PKG")
	canceled := errors.New("fixture chooser canceled")
	runErr := errors.New("fixture installer quit")
	reply, chooserErr := []byte(nil), canceled
	runs, selections := 0, 0
	c := systemInstallRequiredWith("darwin", nil, func(ctx context.Context, command string, args ...string) ([]byte, error) {
		selections++
		if command != "/usr/bin/osascript" || len(args) != 2 || args[0] != "-e" {
			t.Fatalf("unexpected chooser %q %v", command, args)
		}
		return reply, chooserErr
	}, nil, func(c context.Context, out io.Writer, command string, args ...string) error {
		runs++
		if command != "/usr/bin/open" || c != ctx || out != io.Discard || !slices.Equal(args, []string{"-W", "-n", "-b", "com.apple.installer", path}) {
			t.Fatalf("unexpected installer %q %v", command, args)
		}
		return runErr
	})
	if c.Apply == nil || selections != 0 || runs != 0 {
		t.Fatal("merely showing package advice started chooser or installer")
	}
	if err := c.Apply(ctx, nil, io.Discard, ""); !errors.Is(err, canceled) || runs != 0 {
		t.Fatalf("canceled chooser launched installer: %v", err)
	}
	chooserErr = nil
	for _, invalid := range []string{"relative.pkg\n", filepath.Join(filepath.Dir(path), "fixture.txt") + "\n"} {
		reply = []byte(invalid)
		if err := c.Apply(ctx, nil, io.Discard, ""); err == nil || runs != 0 {
			t.Fatalf("invalid choice launched installer: %v", err)
		}
	}
	reply = []byte(path + "\r\n")
	if err := c.Apply(ctx, nil, io.Discard, ""); !errors.Is(err, runErr) || runs != 1 || selections != 4 {
		t.Fatalf("valid selection not delegated with its actual result: %v / %d / %d", err, runs, selections)
	}
}
