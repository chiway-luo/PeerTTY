package console

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestIdentityAndInactiveCommands(t *testing.T) {
	dir := t.TempDir()
	key, err := IdentityPath(dir, "")
	if err != nil || key != filepath.Join(dir, "device.key") {
		t.Fatal(key, err)
	}
	if got, err := IdentityPath("", key); err != nil || got != key {
		t.Fatal(got, err)
	}
	if _, err = IdentityPath(dir, key); err == nil {
		t.Fatal("ambiguous identity accepted")
	}
	var out bytes.Buffer
	if err = DisplayStatus(t.Context(), key, &out); err != nil || !strings.Contains(out.String(), active.ErrInactive.Error()) {
		t.Fatal("status", out.String(), err)
	}
	if err = EndGrant(t.Context(), key, io.Discard); !errors.Is(err, active.ErrInactive) {
		t.Fatal("revoke", err)
	}
	if err = Link(t.Context(), key, nil, io.Discard, io.Discard, RemoteCommand{}); !errors.Is(err, active.ErrInactive) {
		t.Fatal("link", err)
	}
	if _, err = os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only commands created an identity", err)
	}
}

func TestSSHArgumentsMatchSessionAndCommand(t *testing.T) {
	s := active.State{Alias: "device", User: "fixture", SSHConfig: "config with spaces", Identity: "device key"}
	args := sshArgs("peertty", "_link-proxy", s, RemoteCommand{})
	for _, option := range []string{"ServerAliveInterval=5", "ServerAliveCountMax=5", "ConnectTimeout=45"} {
		if !slices.Contains(args, option) {
			t.Fatal("missing SSH timeout", option)
		}
	}
	if slices.Contains(sshArgs("peertty", "_menu-proxy", s, RemoteCommand{}), "ConnectTimeout=45") {
		t.Fatal("short SSH handshake timeout applied to manual pairing")
	}
	if args[0] != "-tt" || !slices.Contains(args, s.SSHConfig) || !slices.Contains(args, s.Identity) {
		t.Fatal(args)
	}
	s.KnownHosts = filepath.Join("dir with spaces", "known%hosts")
	for _, tty := range []bool{false, true} {
		cmd := RemoteCommand{Args: []string{"printf", "a b"}, TTY: tty}
		args = sshArgs("peertty", "_link-proxy", s, cmd)
		flag := "-T"
		if tty {
			flag = "-tt"
		}
		if args[0] != flag || !slices.Equal(args[len(args)-5:], []string{"-l", "fixture", "device", "printf", "a b"}) {
			t.Fatal(args)
		}
		if slices.Contains(args, s.SSHConfig) || !slices.Contains(args, "StrictHostKeyChecking=yes") ||
			!slices.Contains(args, `UserKnownHostsFile="dir with spaces/known%%hosts"`) {
			t.Fatal("incorrect scoped SSH options", args)
		}
	}
}

func TestHostPanelDistinguishesApprovalAndLiveControls(t *testing.T) {
	var out bytes.Buffer
	c := Console{out: &out, fullScreen: true}
	state := active.State{Role: "host", Phase: "waiting", Deadline: time.Now().Add(time.Hour)}
	offer := grant.Ticket{Claims: grant.Claims{SSHUser: "fixture"}}
	answer := grant.Ticket{Claims: grant.Claims{DeviceName: "engineer", SSHLoginKey: []byte{1}}}
	c.hostInputPrompt(state, offer, &answer)
	s := ansi.Strip(out.String())
	for _, part := range []string{"engineer", "fixture", "y 批准", "r 重选", "q 撤销"} {
		if !strings.Contains(s, part) {
			t.Fatal("missing approval information", part)
		}
	}
	out.Reset()
	state.Phase = "ready"
	state.Terminals = 2
	c.hostInputPrompt(state, offer, nil)
	s = ansi.Strip(out.String())
	if !strings.Contains(s, "已连接") || !strings.Contains(s, "已连终端") || !strings.Contains(s, "b 返回") || strings.Contains(s, "y 批准") {
		t.Fatal("wrong live panel", s)
	}
}

func TestHostPanelCanReviewAndDiscardAReceipt(t *testing.T) {
	_, host, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, controller, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	offer, err := grant.NewPairingOffer(host, "offer", "fixture", deadline)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := grant.NewAnswer(controller, offer, "answer")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st := active.State{Role: "host", Phase: "waiting", ID: "fixture", Exchange: filepath.Join(dir, "invite"), Deadline: deadline}
	if err := offer.WriteNew(st.Exchange); err != nil {
		t.Fatal(err)
	}
	reply := filepath.Join(dir, "reply")
	if err := answer.WriteNew(reply); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "input")
	input := strings.Join([]string{"v", filepath.Join(dir, "missing"), reply, "r", "b", ""}, "\n")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out bytes.Buffer
	c := Console{in: in, out: &out, interactive: true, Settings: Settings{KeyPath: filepath.Join(dir, "device.key")}}
	if err := c.watchHost(t.Context(), st); !errors.Is(err, errBack) {
		t.Fatal("could not leave the pending grant", err)
	}
	shown := out.String()
	for _, want := range []string{st.Exchange, ticketBegin, "回执无效", "回执已核验", "授权继续有效"} {
		if !strings.Contains(shown, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(shown, "已批准本次连接") {
		t.Fatal("review alone approved the receipt")
	}
}

func TestNativeSSHRestoresMenuAfterChildError(t *testing.T) {
	var out bytes.Buffer
	c := Console{out: &out, fullScreen: true}
	childErr := errors.New("child exited")
	err := c.nativeSSH(func() error {
		out.WriteString("child")
		return childErr
	})
	if !errors.Is(err, childErr) || out.String() != leaveScreen+erasePage+"child"+enterScreen+erasePage {
		t.Fatal("terminal restoration failed", err, out.String())
	}
}

func TestTicketInputFormatsAndTruncation(t *testing.T) {
	ticket := grant.Ticket{Claims: grant.Claims{Session: "sample", SDP: "local offer"}}
	var pasted strings.Builder
	if err := writeTicketText(&pasted, ticket); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "invitation with spaces.offer")
	if err := ticket.WriteNew(path); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{string(raw), pasted.String(), path} {
		got, err := readTicket(input)
		if err != nil || got.Claims.Session != ticket.Claims.Session || got.Claims.SDP != ticket.Claims.SDP {
			t.Fatalf("different invitation after import: %v", err)
		}
	}
	for _, input := range []string{dir, filepath.Join(dir, "missing"), "{", ticketBegin + "\nmissing footer"} {
		if _, err := readTicket(input); err == nil {
			t.Fatal("accepted incomplete invitation or invalid path")
		}
	}
	for _, invalid := range []string{pasted.String() + pasted.String(), "two\ncommands", "\x1b[H", ticketEnd} {
		if _, err := pastedValue(invalid); !errors.Is(err, incompletePaste) {
			t.Fatalf("ambiguous clipboard selection: %v", err)
		}
	}
}

func TestLinkLaunchesOnlyForReadyController(t *testing.T) {
	for _, s := range []active.State{{Role: "host", Phase: "ready"}, {Role: "control", Phase: "waiting"}} {
		if err := linkSSH(t.Context(), "", s, nil, io.Discard, io.Discard, RemoteCommand{}, nil); err == nil {
			t.Fatalf("started SSH for %s/%s", s.Role, s.Phase)
		}
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("native OpenSSH client unavailable")
	}
	s := active.State{ID: "grant-01", Role: "control", Phase: "ready", Alias: "fixture", User: "operator"}
	in, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	key := filepath.Join(t.TempDir(), "local.key")
	childErr := errors.New("fixture exit")
	check := func(cmd *exec.Cmd) error {
		for _, env := range []string{"PEERTTY_LINK_KEY=" + key, "PEERTTY_LINK_ID=" + s.ID} {
			if !slices.Contains(cmd.Env, env) {
				t.Errorf("missing grant binding %s", env)
			}
		}
		if cmd.Stdin != in || !slices.Equal(cmd.Args[len(cmd.Args)-3:], []string{"operator", "fixture", "hostname"}) {
			t.Errorf("wrong SSH invocation %q", cmd.Args)
		}
		return childErr
	}
	err = linkSSH(t.Context(), key, s, in, io.Discard, io.Discard, RemoteCommand{Args: []string{"hostname"}}, check)
	if !errors.Is(err, childErr) {
		t.Fatalf("SSH exit lost: %v", err)
	}
}
