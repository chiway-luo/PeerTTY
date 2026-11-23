package console

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/filelock"
	"peertty/internal/grant"
	"peertty/internal/localssh"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == active.Command {
		if active.Main(context.Background()) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestTerminalTicketPasteLeavesNextInput(t *testing.T) {
	in := grant.Ticket{Claims: grant.Claims{SDP: strings.Repeat("candidate ", 1200)}}
	var copied strings.Builder
	if err := writeTicketText(&copied, in); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(copied.String(), "\n") {
		if len(line) > 80 {
			t.Fatal("paste exceeds a terminal line")
		}
	}
	keyboard := strings.NewReader(strings.ReplaceAll(copied.String(), "\n", "\r\n") + "alice\n")
	first, err := readEntry(keyboard)
	if err != nil || !isTicketText(first) {
		t.Fatal("reading pasted ticket", err)
	}
	ticket, err := readTicket(first)
	if err != nil || ticket.Claims.SDP != in.Claims.SDP {
		t.Fatal("pasted payload differs", err)
	}
	if next, err := readEntry(keyboard); err != nil || next != "alice" {
		t.Fatal("paste consumed the next prompt", err)
	}
}

func TestBracketedPasteIsOneEntry(t *testing.T) {
	original := grant.Ticket{Claims: grant.Claims{SDP: strings.Repeat("candidate ", 1500)}}
	var block strings.Builder
	if err := writeTicketText(&block, original); err != nil {
		t.Fatal(err)
	}
	for _, end := range []string{"", "\n", "\r\n"} {
		for _, sep := range []string{"\n", "\r\n", "\r"} {
			selected := "邀请文本" + sep + strings.ReplaceAll(strings.TrimSpace(block.String()), "\n", sep) + end
			input := strings.NewReader(pasteStart + selected + pasteEnd + "\nnext\n")
			value, err := readEntry(input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readTicket(value)
			if err != nil || got.Claims.SDP != original.Claims.SDP {
				t.Fatalf("framed ticket corrupted: %v", err)
			}
			if next, err := readEntry(input); next != "next" || err != nil {
				t.Fatal("paste consumed the following prompt")
			}
		}
	}
	for _, bad := range []string{ticketBegin + "\nabc", block.String() + block.String(), strings.Repeat("x", maxPaste+1)} {
		in := strings.NewReader(pasteStart + bad + pasteEnd + "\nnext\n")
		if _, err := readEntry(in); err == nil {
			t.Fatal("accepted incomplete, ambiguous, or oversized paste")
		}
		if next, err := readEntry(in); err != nil || next != "next" {
			t.Fatal("rejected paste left input behind")
		}
	}
	in := strings.NewReader(pasteStart + block.String() + "y\n" + pasteEnd + "\nq\n")
	value, err := readEntry(in)
	if err != nil || !strings.HasSuffix(value, ticketEnd) {
		t.Fatal("did not extract exactly one ticket from the selection")
	}
	if next, err := readEntry(in); err != nil || next != "q" {
		t.Fatal("text copied with the ticket became a separate approval")
	}
}

type transcript struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	changed chan struct{}
}

func (l *transcript) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.buf.Write(b)
	select {
	case l.changed <- struct{}{}:
	default:
	}
	return n, err
}
func (l *transcript) wait(t *testing.T, s string) string {
	t.Helper()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	for {
		l.mu.Lock()
		text := l.buf.String()
		l.mu.Unlock()
		if strings.Contains(text, s) {
			return text
		}
		select {
		case <-l.changed:
		case <-timer.C:
			t.Fatalf("missing %q in menu", s)
		}
	}
}

func TestExpiredHostReturnsToSameMenu(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a detached host and waits for its grant to expire")
	}
	in, keys, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	defer keys.Close()
	dir := t.TempDir()
	log := &transcript{changed: make(chan struct{}, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	done := make(chan error, 1)
	// This test exercises grant expiration independently of the test machine's SSH setup.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprintln(c, "SSH-2.0-menu_fixture")
			c.Close()
		}
	}()
	go func() {
		done <- Run(ctx, Settings{StateDir: dir, TTL: 600 * time.Millisecond, SSHPort: ln.Addr().(*net.TCPAddr).Port}, in, log)
	}()
	fmt.Fprint(keys, "2\n\n")
	text := log.wait(t, hostPrompt)
	_, rest, ok := strings.Cut(text, "邀请文件  ")
	if !ok {
		t.Fatal("no offer file")
	}
	path, _, _ := strings.Cut(rest, "\n")
	log.wait(t, "授权已到期")
	// Supply both lines after expiry. The outstanding read from the host
	// prompt must be consumed by the menu, not lost in a retired goroutine.
	fmt.Fprint(keys, "3\n-\n22\n0\n")
	log.wait(t, "连接设置已应用")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("offer survived expiry", err)
	}
	lease, err := grant.LeaseIdentity(filepath.Join(dir, "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
}

func TestSSHMenuRepairsOnlyOnSelectionAndRechecks(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		applied     bool
	}{{"return", "0\n", false}, {"retry_then_return", "2\n0\n", false}, {"repair", "1\n", true}} {
		t.Run(tc.name, func(t *testing.T) {
			in, keys, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			fmt.Fprint(keys, tc.input)
			keys.Close()
			var out bytes.Buffer
			c := Console{in: in, out: &out}
			applied := false
			inspect := func() localssh.Check {
				if applied {
					return localssh.Check{Ready: true, Message: "ready"}
				}
				return localssh.Check{Message: "missing", Action: "repair", Apply: func(context.Context, *os.File, io.Writer, string) error {
					applied = true
					return nil
				}}
			}
			err = c.checkSSH(context.Background(), true, inspect)
			if applied != tc.applied || (err == nil) != tc.applied || (!tc.applied && err != errBack) ||
				strings.Contains(out.String(), "ready") != tc.applied {
				t.Fatalf("applied=%t err=%v output=%q", applied, err, out.String())
			}
		})
	}
}

func TestSSHMenuChangesPortAndRechecks(t *testing.T) {
	in, keys, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	fmt.Fprint(keys, "3\ninvalid\n2222\n")
	keys.Close()
	var log bytes.Buffer
	c := Console{Settings: Settings{SSHPort: 22}, in: in, out: &log}
	err = c.checkSSH(context.Background(), true, func() localssh.Check {
		return localssh.Check{Ready: c.SSHPort == 2222}
	})
	if err != nil || c.SSHPort != 2222 || !strings.Contains(log.String(), "请输入 1–65535") {
		t.Fatalf("port %d, err %v, output %q", c.SSHPort, err, log.String())
	}
}

func TestMenuUsesIdentityInInvitation(t *testing.T) {
	dir := t.TempDir()
	self, err := grant.NewIdentity(filepath.Join(dir, "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	_, host, _ := ed25519.GenerateKey(rand.Reader)
	offer, err := grant.NewPairingOffer(host, "fixture", "labuser", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var invitation strings.Builder
	if err = writeTicketText(&invitation, offer); err != nil {
		t.Fatal(err)
	}
	in, keys, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	defer keys.Close()
	log := &transcript{changed: make(chan struct{}, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Settings{StateDir: dir, TTL: time.Minute, SSHPort: 22}, in, log) }()

	// Try a bracketed menu paste, then an invitation at the role prompt.
	fmt.Fprint(keys, pasteStart, invitation.String(), pasteEnd, "\n\nq\n1\n", invitation.String(), "other-user\nq\n")
	// A targeted v1 invitation is accepted only by its named recipient.
	old, err := grant.NewOffer(host, self, "legacy", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTicketText(keys, old); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(keys, "q\n")
	offer.Claims.SDP += "tampered"
	if err = writeTicketText(keys, offer); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(keys, "0\n")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	transcript := log.buf.String()
	if strings.Count(transcript, "已收到邀请文本") != 4 || strings.Count(transcript, "邀请签名已核验") != 3 ||
		strings.Count(transcript, "SSH 登录私钥路径") != 2 || !strings.Contains(transcript, "邀请校验失败") ||
		strings.Contains(transcript, "设备指纹 >") {
		t.Fatal("menu did not pair from the signed invitation alone or accepted a tampered offer")
	}
}

func TestProxyStopsIfOwningMenuDisappears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "received.offer")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	owner, err := filelock.Try(path)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := handoff{Offer: path}
	go h.watchMenu(ctx, cancel, make(chan struct{}))
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("orphan proxy still waiting for approval")
	}
}

func TestPipedMenuKeepsPlainTranscript(t *testing.T) {
	in, keys, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	fmt.Fprint(keys, "/help\n/status\n/clipboard\n/clipboard\n0\n")
	keys.Close()
	var log bytes.Buffer
	if err = Run(t.Context(), Settings{StateDir: t.TempDir(), TTL: time.Hour, SSHPort: 22}, in, &log); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), "\x1b") || strings.Count(log.String(), "点对点远程终端") != 1 || !strings.Contains(log.String(), "/link") || !strings.Contains(log.String(), "没有有效") {
		t.Fatal("unexpected menu transcript", log.String())
	}
}

func TestMenuReplacesPages(t *testing.T) {
	in, keys, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	fmt.Fprint(keys, "/help\n/status\n\n3\nnone\ninvalid\n2222\n3\nq\n/link\n\n0\n")
	keys.Close()
	var output bytes.Buffer
	c := Console{
		Settings: Settings{KeyPath: filepath.Join(t.TempDir(), "device.key"), SSHPort: 22},
		in:       in, out: &output, fullScreen: true,
	}
	if err := c.menu(t.Context()); err != nil {
		t.Fatal(err)
	}
	var pages []string
	for _, page := range strings.Split(output.String(), erasePage) {
		if page != "" {
			pages = append(pages, page)
		}
	}
	want := []string{
		"点对点远程终端", "关闭菜单", "当前没有有效", "点对点远程终端",
		"设备密钥", "本机 SSH 端口 [22]", "请输入 1–65535", "连接设置已应用",
		"设备密钥", "点对点远程终端", "操作结束", "点对点远程终端",
	}
	if len(pages) != len(want) {
		t.Fatalf("got %d pages, want %d: %q", len(pages), len(want), pages)
	}
	for i, marker := range want {
		if !strings.Contains(pages[i], marker) || !strings.Contains(pages[i], "> ") && !strings.Contains(pages[i], "❯ ") {
			t.Errorf("page %d should contain %q and a prompt: %q", i, marker, pages[i])
		}
	}
}

func TestLongReceiptKeepsFilePathVisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.answer")
	answer := grant.Ticket{Claims: grant.Claims{SDP: strings.Repeat("candidate ", 1200)}}
	if err := answer.WriteNew(path); err != nil {
		t.Fatal(err)
	}
	log := &transcript{changed: make(chan struct{}, 1)}
	c := Console{out: log, fullScreen: true}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.waitControl(ctx, active.State{Phase: "waiting", Exchange: path}, true)
	}()
	printed := log.wait(t, "将回执发给被控方")
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatal(err)
	}
	_, footer, ok := strings.Cut(printed, ticketEnd)
	if !ok || !strings.Contains(footer, "回执文件  "+path) {
		t.Fatal("the receipt scrolled its file path out of view")
	}
}

func TestAuthorizationHours(t *testing.T) {
	for _, tc := range []struct {
		entries string
		hours   int
		retries int
	}{
		{"\n", 1, 0}, {"1\n", 1, 0}, {"0\n25\n1.5\n24\n", 24, 3},
	} {
		in, keys, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprint(keys, tc.entries)
		keys.Close()
		var output bytes.Buffer
		c := Console{Settings: Settings{TTL: time.Hour}, in: in, out: &output}
		d, err := c.askDuration(t.Context(), localssh.Check{})
		in.Close()
		if err != nil || d != time.Duration(tc.hours)*time.Hour || strings.Count(output.String(), "请输入 1 到 24") != tc.retries {
			t.Fatal(d, err, output.String())
		}
	}
}

func TestDurationScreenNoticesWhenSSHCloses(t *testing.T) {
	if color, mark := sshIndicator(localssh.Check{Ready: true, Closed: true}); color == "32" || mark == "✓" {
		t.Fatal("closed port with valid temporary configuration is shown as listening")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			fmt.Fprint(c, "SSH-2.0-fixture\r\n")
			io.Copy(io.Discard, c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	initial := localssh.ProbeListener(t.Context(), port)
	if !initial.Ready || initial.Closed {
		t.Fatalf("expected a listening SSH service: %+v", initial)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 16*time.Second)
	defer cancel()
	updates := watchListener(ctx, port, initial)
	ln.Close()
	select {
	case state := <-updates:
		if state.Ready || !state.Closed {
			t.Fatalf("closed SSH still available: %+v", state)
		}
	case <-ctx.Done():
		t.Fatal("duration screen kept the old SSH status")
	}
}
