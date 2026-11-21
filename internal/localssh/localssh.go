// Package localssh opens the controlled machine's loopback SSH endpoint.
package localssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"peertty/internal/grant"
)

const GuardCommand = "_local-sshd"
const startupTimeout = 10 * time.Second

// Conn owns an optional session-local OpenSSH process, never a pre-existing service.
type Conn struct {
	*net.TCPConn
	guard *guard
	input *bufio.Reader
}

func (c *Conn) Temporary() bool { return c.guard != nil }

func (c *Conn) Read(p []byte) (int, error) {
	if c.input != nil {
		return c.input.Read(p)
	}
	return c.TCPConn.Read(p)
}

// Release runs after the SSH bridge has closed its connection.
func (c *Conn) Release() error {
	if c.guard == nil {
		return nil
	}
	return c.guard.close()
}

func dial(ctx context.Context, addr string) (*net.TCPConn, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

// Open is called only after the local owner has approved the signed answer and
// ICE has selected the peer. Only a refused default port triggers activation.
func Open(ctx context.Context, port int) (*Conn, error) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	c, err := dial(ctx, addr)
	if err == nil {
		return &Conn{TCPConn: c}, nil
	}
	if port != 22 || !errors.Is(err, refused) || ctx.Err() != nil {
		return nil, fmt.Errorf("连接本机 SSH %s: %w", addr, err)
	}
	return activate(ctx, addr)
}

type guard struct {
	input   io.WriteCloser
	process *os.Process
	done    chan struct{}
	err     error // read after done closes
	lines   chan string
	once    sync.Once
}

// Native sshd can log throughout a session. Keep a bounded tail for failures.
type diagnosticTail []byte

func (d *diagnosticTail) Write(p []byte) (int, error) {
	const limit = 2048
	n := len(p)
	if n >= limit {
		*d = append((*d)[:0], p[n-limit:]...)
	} else {
		skip := max(0, len(*d)+n-limit)
		*d = append((*d)[skip:], p...)
	}
	return n, nil
}

func (g *guard) close() error {
	g.once.Do(func() { _ = g.input.Close() })
	select {
	case <-g.done:
		return g.err
	case <-time.After(4 * time.Second):
	}
	err := g.process.Kill()
	select {
	case <-g.done:
		return errors.Join(err, g.err)
	case <-time.After(2 * time.Second):
		return errors.Join(err, errors.New("临时 OpenSSH 进程未在规定时间内退出"))
	}
}

func (g *guard) line(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case line, ok := <-g.lines:
		if ok {
			return line, nil
		}
		return "", errors.New("本机 SSH 启动进程已退出")
	}
}

func (g *guard) expect(ctx context.Context, want string) error {
	line, err := g.line(ctx)
	if err == nil && line != want {
		return fmt.Errorf("本机 SSH 启动失败：%s", line)
	}
	return err
}

func activate(ctx context.Context, addr string) (*Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("临时 SSH 服务需要授权截止时间")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return attach(ctx, addr, guardCmd(exe, strconv.FormatInt(deadline.UnixMilli(), 10)))
}

func attach(ctx context.Context, addr string, cmd *exec.Cmd) (_ *Conn, result error) {
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	status, output, err := os.Pipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	var diagnostic diagnosticTail
	cmd.Stdout, cmd.Stderr = output, &diagnostic
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		input.Close()
		status.Close()
		output.Close()
		return nil, fmt.Errorf("启动本机 OpenSSH: %w", err)
	}
	output.Close()
	g := &guard{input: input, process: cmd.Process, done: make(chan struct{}), lines: make(chan string, 2)}
	go func() {
		scan := bufio.NewScanner(status)
		for i := 0; i < 2 && scan.Scan(); i++ {
			g.lines <- scan.Text()
		}
		status.Close()
		close(g.lines)
	}()
	go func() {
		if err := cmd.Wait(); err != nil {
			g.err = fmt.Errorf("临时 SSH: %w (%s)", err, strings.TrimSpace(string(diagnostic)))
		}
		close(g.done)
	}()
	defer func() {
		if result != nil {
			result = errors.Join(result, g.close())
		}
	}()
	start, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if addr == "127.0.0.1:0" {
		line, err := g.line(start)
		if err != nil {
			return nil, err
		}
		number, ok := strings.CutPrefix(line, "READY ")
		port, err := strconv.ParseUint(number, 10, 16)
		if !ok || err != nil || port == 0 {
			return nil, errors.New("临时 SSH 服务没有返回有效回环端口")
		}
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	} else if err := g.expect(start, "READY"); err != nil {
		return nil, err
	}
	c, err := dial(start, addr)
	if err != nil {
		return nil, err
	}
	if _, err = fmt.Fprintln(input, c.LocalAddr().(*net.TCPAddr).Port); err == nil {
		err = g.expect(start, "ATTACHED")
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	// Do not report a successful cold start until native OpenSSH identifies
	// itself. Peek keeps its identification intact for the real SSH client.
	until, _ := start.Deadline()
	_ = c.SetReadDeadline(until)
	stop := context.AfterFunc(start, func() { c.Close() })
	inputBuffer := bufio.NewReader(c)
	header, err := inputBuffer.Peek(len("SSH-2.0-"))
	if !stop() || err != nil || string(header) != "SSH-2.0-" {
		c.Close()
		return nil, fmt.Errorf("临时 OpenSSH 未能完成启动握手 (%v)", err)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	return &Conn{TCPConn: c, guard: g, input: inputBuffer}, nil
}

// Serve runs in a dedicated local process. Closing the parent's private pipe
// cancels startup or the active server, including on abnormal parent exit.
func Serve(parent context.Context, args []string, in io.Reader, out io.Writer) error {
	var mode, dir string
	if len(args) == 3 && (args[1] == "login-open" || args[1] == "login-closed") {
		mode, dir = args[1], args[2]
	} else if len(args) != 1 {
		return errors.New("缺少本机授权截止时间")
	}
	ms, err := strconv.ParseInt(args[0], 10, 64)
	until := time.UnixMilli(ms)
	if err != nil || !until.After(time.Now()) || time.Until(until) > grant.MaxTTL {
		return errors.New("无效的本机授权截止时间")
	}
	ctx, cancel := context.WithDeadline(parent, until)
	defer cancel()
	ports := make(chan int, 1)
	go func() {
		// A single short decimal port followed by EOF is the entire protocol.
		r := bufio.NewReaderSize(in, 32)
		line, err := r.ReadSlice('\n')
		n, convErr := strconv.Atoi(strings.TrimSpace(string(line)))
		if err == nil && convErr == nil && n > 0 && n <= 65535 {
			ports <- n
			_, _ = r.ReadByte()
		}
		cancel()
	}()
	return serveLocal(ctx, ports, out, mode, dir)
}

func peerPort(ctx context.Context, ports <-chan int, out io.Writer, ready string) (int, error) {
	if _, err := fmt.Fprintln(out, ready); err != nil {
		return 0, err
	}
	select {
	case p := <-ports:
		return p, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func cmdError(cmd *exec.Cmd, err error, details string) error {
	return fmt.Errorf("%s: %w (%s)", cmd.Path, err, strings.TrimSpace(details))
}
