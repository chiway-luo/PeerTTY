package console

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
	"peertty/internal/localssh"
)

func TestControllerSelectsExplicitLoginWithoutStartingUnapprovedSession(t *testing.T) {
	_, operatorKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	remoteSSHHost, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "operator")
	deadline := time.Now().Add(time.Minute)
	newOffer := func(key ed25519.PrivateKey, account string, hk ed25519.PublicKey, deadline time.Time) grant.Ticket {
		t.Helper()
		ticket, err := grant.NewLoginOffer(key, "fixture SDP", account, hk, deadline)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixtureCode.Seal(&ticket); err != nil {
			t.Fatal(err)
		}
		return ticket
	}
	scoped := newOffer(host, "robot", remoteSSHHost, deadline)
	standard := newOffer(host, "robot", nil, deadline)
	noSuggestion := newOffer(host, "", nil, deadline)
	self := newOffer(operatorKey, "robot", nil, deadline)
	expired := newOffer(host, "robot", nil, time.Now().Add(-time.Minute))
	secretPath := filepath.Join(dir, "dummy-key")
	if err := os.WriteFile(secretPath, []byte("local fixture"), 0600); err != nil {
		t.Fatal(err)
	}

	startErr := errors.New("worker start failed")
	statusErr := errors.New("status unavailable")
	for _, tc := range []struct {
		name                                  string
		offer                                 grant.Ticket
		input                                 []string
		priorCodes                            []string
		promptForInvite, useText, sshNotReady bool
		status                                active.State
		statusErr                             error
		wantErr, wantUser, wantIdentity       string
		wantScoped                            bool
	}{
		{name: "scoped default", offer: scoped, input: []string{""}, wantUser: "robot", wantScoped: true, useText: true},
		{name: "correct code on the same invite", offer: scoped, priorCodes: []string{"incomplete", strings.Repeat("F", 32)}, input: []string{""}, wantUser: "robot", wantScoped: true, promptForInvite: true},
		{name: "cancel after a typo", offer: scoped, priorCodes: []string{"incomplete", "q"}, wantErr: "返回菜单"},
		{name: "system SSH explicitly", offer: scoped, input: []string{"/ssh", "", ""}, wantUser: "robot"},
		{name: "alternate account and key", offer: scoped, input: []string{"operator", secretPath}, wantUser: "operator", wantIdentity: secretPath},
		{name: "normal invitation", offer: standard, input: []string{"", ""}, wantUser: "robot", promptForInvite: true},
		{name: "no account in invitation", offer: noSuggestion, input: []string{"operator", ""}, wantUser: "operator"},
		{name: "no scoped shortcut to a different account", offer: scoped, input: []string{"/ssh", "operator", ""}, wantUser: "operator"},
		{name: "preflight abort", sshNotReady: true, input: []string{"q"}, wantErr: "返回菜单"},
		{name: "abort invitation prompt", promptForInvite: true, input: []string{"q"}, wantErr: "返回菜单"},
		{name: "missing invitation file", wantErr: "missing file"},
		{name: "same image can pair", offer: self, input: []string{"", ""}, wantUser: "robot"},
		{name: "reject expired invitation", offer: expired, wantErr: "邀请校验失败"},
		{name: "device already in use", offer: scoped, status: active.State{Role: "host"}, wantErr: grant.ErrInUse.Error()},
		{name: "old receipt missing", offer: scoped, status: active.State{Role: "control", Exchange: filepath.Join(dir, "missing-answer")}, wantErr: "missing file"},
		{name: "cannot read active status", offer: scoped, statusErr: statusErr, wantErr: statusErr.Error()},
		{name: "abort username", offer: scoped, input: []string{"q"}, wantErr: "返回菜单"},
		{name: "abort alternative account", offer: scoped, input: []string{"/ssh", "q"}, wantErr: "返回菜单"},
		{name: "reject empty user without suggested name", offer: noSuggestion, input: []string{""}, wantErr: "有效的 SSH 用户名"},
		{name: "abort private key prompt", offer: standard, input: []string{"", "q"}, wantErr: "返回菜单"},
		{name: "missing private key", offer: standard, input: []string{"", filepath.Join(dir, "absent")}, wantErr: "missing file"},
		{name: "reject private key directory", offer: standard, input: []string{"", dir}, wantErr: "普通文件"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			invite := filepath.Join(t.TempDir(), "invitation")
			if len(tc.offer.Signature) > 0 {
				if tc.useText {
					var data bytes.Buffer
					if err := writeTicketText(&data, tc.offer); err != nil {
						t.Fatal(err)
					}
					invite = strings.TrimSpace(data.String())
				} else if err := tc.offer.WriteNew(invite); err != nil {
					t.Fatal(err)
				}
			}
			input := append(append(slices.Clone(tc.priorCodes), string(fixtureCode)), tc.input...)
			if tc.sshNotReady || tc.name == "abort invitation prompt" {
				input = tc.input
			}
			if tc.promptForInvite {
				if tc.name != "abort invitation prompt" {
					input = append([]string{invite}, input...)
				}
				invite = ""
			}
			inputPath := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(inputPath, []byte(strings.Join(input, "\n")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			in, err := os.Open(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			ui := Console{Settings: Settings{KeyPath: keyPath, STUN: "none"}, in: in, out: &log}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			var calls int
			err = ui.controlWith(ctx, invite, controllerServices{
				check: func() localssh.Check { return localssh.Check{Ready: !tc.sshNotReady} },
				status: func(_ context.Context, key string) (active.State, error) {
					if key != keyPath {
						t.Fatalf("status requested for wrong device %q", key)
					}
					if tc.statusErr != nil || tc.status.Role != "" {
						return tc.status, tc.statusErr
					}
					return active.State{}, active.ErrInactive
				},
				start: func(_ context.Context, opts active.Options) (active.State, error) {
					calls++
					if opts.Role != "control" || opts.Key != keyPath || opts.STUN != "none" || opts.User != tc.wantUser ||
						opts.Identity != tc.wantIdentity || opts.Scoped != tc.wantScoped || !bytes.Equal(opts.Offer.Signature, tc.offer.Signature) {
						t.Fatalf("unexpected controller settings: user=%q scoped=%v", opts.User, opts.Scoped)
					}
					return active.State{}, startErr
				},
			})
			if tc.wantUser != "" {
				if calls != 1 || !errors.Is(err, startErr) {
					t.Fatalf("start calls = %d; error = %v", calls, err)
				}
				if len(tc.priorCodes) != 0 && (strings.Count(log.String(), "邀请文件路径或整段邀请文本") != 1 ||
					strings.Count(log.String(), "单独提供的一次性配对码") != 3 || !strings.Contains(log.String(), "与本次凭证不匹配")) {
					t.Fatal("a mistyped code must allow another attempt on the same invitation")
				}
			} else {
				match := err != nil && strings.Contains(err.Error(), tc.wantErr)
				if tc.wantErr == "missing file" {
					match = errors.Is(err, os.ErrNotExist)
				}
				if calls != 0 || !match {
					t.Fatalf("start calls = %d; error = %v; wanted %q\n%s", calls, err, tc.wantErr, log.String())
				}
			}
		})
	}
}

func TestPairingCodeStopsAtInvitationExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ui := &Console{out: io.Discard, pending: make(chan line)}
		offer := grant.Ticket{Claims: grant.Claims{ExpiresMS: time.Now().Add(time.Minute).UnixMilli()}}
		if _, err := ui.askPairingCode(t.Context(), offer); err == nil || !strings.Contains(err.Error(), "邀请已到期") {
			t.Fatalf("expired invitation remained at the retry prompt: %v", err)
		}
	})
}

func TestControllerReusesOnlyReceiptForSelectedInvitation(t *testing.T) {
	_, operatorKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := grant.NewLoginOffer(host, "fixture invite", "robot", nil, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	other, err := grant.NewLoginOffer(host, "other invite", "robot", nil, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, phase, input   string
		newWorker, different bool
	}{
		{name: "existing waiting grant", phase: "waiting"},
		{name: "existing ready grant shows receipt without opening terminal", phase: "ready"},
		{name: "other invitation cannot replace active grant", phase: "waiting", different: true},
		{name: "new worker publishes receipt and stays pending approval", phase: "waiting", newWorker: true, input: string(fixtureCode) + "\n\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			invitePath, receiptPath := filepath.Join(dir, "offer"), filepath.Join(dir, "receipt")
			selected := offer
			if tc.different {
				selected = other
			}
			if err := fixtureCode.Seal(&selected); err != nil {
				t.Fatal(err)
			}
			if err := selected.WriteNew(invitePath); err != nil {
				t.Fatal(err)
			}
			receipt, err := grant.NewLoginAnswer(operatorKey, offer, "fixture receipt", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = receipt.WriteNew(receiptPath); err != nil {
				t.Fatal(err)
			}
			st := active.State{ID: "fixture", Role: "control", Phase: tc.phase, Exchange: receiptPath, Deadline: offer.Deadline()}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			input, out := sshMenuInput(t, tc.input)
			c := Console{in: input, out: out, autoCopy: true, Settings: Settings{KeyPath: filepath.Join(dir, "device"), STUN: "none"}}
			copies, starts := 0, 0
			c.copyToClipboard = func(_ context.Context, _ io.Writer, ticket grant.Ticket) (string, error) {
				if !bytes.Equal(ticket.Signature, receipt.Signature) {
					return "", errors.New("wrong receipt")
				}
				copies++
				cancel()
				return "fixture receipt copied", nil
			}
			err = c.controlWith(ctx, invitePath, controllerServices{
				check: func() localssh.Check { return localssh.Check{Ready: true} },
				status: func(context.Context, string) (active.State, error) {
					if tc.newWorker {
						return active.State{}, active.ErrInactive
					}
					return st, nil
				},
				start: func(_ context.Context, opts active.Options) (active.State, error) {
					starts++
					if opts.User != "robot" || !bytes.Equal(opts.Offer.Signature, selected.Signature) {
						return active.State{}, errors.New("wrong start options")
					}
					return st, nil
				},
			})
			if tc.different {
				if !errors.Is(err, grant.ErrInUse) || starts != 0 || copies != 0 {
					t.Fatalf("unrelated invitation reused old grant: %v, starts=%d copies=%d", err, starts, copies)
				}
			} else if !errors.Is(err, context.Canceled) || copies != 1 || (starts == 1) != tc.newWorker || starts > 1 {
				t.Fatalf("receipt was not shown exactly once: %v, starts=%d copies=%d; %s", err, starts, copies, out.String())
			}
		})
	}
}

func TestValidSSHUserRefusesOptionLikeNonPrintableOrOversizedAccounts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"robot", true},
		{"操作员", true},
		{strings.Repeat("r", 256), true},
		{strings.Repeat("r", 257), false},
		{"-robot", false},
		{"robot name", false},
		{"robot\x00", false},
	} {
		if ok := validSSHUser(tc.name); ok != tc.valid {
			t.Fatalf("unexpected account name classification for %q: %v", tc.name, ok)
		}
	}
}
