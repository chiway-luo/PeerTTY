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
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Check describes the current machine. A proposed action only runs when the
// local user selects it in the terminal.
type Check struct {
	Ready           bool
	Closed          bool // loopback refused the connection during this check
	ScopedOnly      bool // only the per-grant SSH configuration passed
	Message, Detail string
	Action          string
	// When PackageExt is set, the console passes the chosen local file to Apply.
	PackageExt string
	Apply      func(context.Context, *os.File, io.Writer, string) error
	// A Windows UAC restart needs the original menu's device identity and settings.
	StartAdmin func([]string) error
}

func systemAction(message, label, path string, args ...string) Check {
	return Check{Message: message, Action: label, Apply: func(ctx context.Context, in *os.File, out io.Writer, _ string) error {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, out
		return cmd.Run()
	}}
}

// ToolPath resolves an OpenSSH client executable (ssh, scp, sftp) via PATH or the OS default location.
func ToolPath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return systemTool(name)
	}
	return path, nil
}

// ClientPath is also used when launching the actual OpenSSH client.
func ClientPath() (string, error) { return ToolPath("ssh") }

func CheckClient() Check {
	if _, err := ClientPath(); err != nil {
		return missingOpenSSH(false)
	}
	return Check{Ready: true, Message: "本机 SSH 客户端已就绪。"}
}

// CheckHost probes only loopback. The session remains responsible for starting
// a temporary service after approval if the default port is still closed.
func CheckHost(ctx context.Context, port int) Check {
	state := ProbeListener(ctx, port)
	if !state.Closed || port != 22 {
		return state
	}
	stopped := checkStopped(ctx)
	stopped.Closed = true
	stopped.Detail = strings.TrimSpace(state.Detail + "\n" + stopped.Detail)
	return stopped
}

// VacancyProbe is a passive hint for a port just observed with a listener.
// Reuse ignores old TIME_WAIT sockets. Some wildcard listeners also allow a
// reusable bind on loopback, so use an exclusive bind for those listeners.
// A successful hint must still be confirmed by an actual SSH probe.
func VacancyProbe(port int) func() bool {
	reuse := bindLoopback(port, true) != nil
	return func() bool { return bindLoopback(port, reuse) == nil }
}

// ProbeListener only observes the SSH banner. It never prepares a service.
func ProbeListener(ctx context.Context, port int) Check {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := dial(probe, addr)
	if err == nil {
		defer c.Close()
		until, _ := probe.Deadline()
		_ = c.SetReadDeadline(until)
		stop := context.AfterFunc(probe, func() { c.Close() })
		defer stop()
		if hasSSHBanner(c) {
			return Check{Ready: true, Message: "本机 " + addr + " 的 SSH 服务可用。"}
		}
		return Check{Message: addr + " 已有程序监听，未收到 SSH 标识。"}
	}
	if !errors.Is(err, refused) {
		return Check{Message: "无法检查本机 " + addr + "。", Detail: err.Error()}
	}
	state := Check{Closed: true, Message: "本机 " + addr + " 没有服务监听。"}
	if port != 22 {
		state.Detail = "请选择已有 SSH 服务的端口，或改用 22 以启用会话临时服务。"
	} else if runtime.GOOS == "darwin" {
		state.Detail = "要使用系统 SSH，请在“系统设置 → 通用 → 共享”中打开“远程登录”，并允许当前账号访问。"
	}
	return state
}

func hasSSHBanner(r io.Reader) bool {
	// OpenSSH permits text lines before its protocol identification.
	reader := bufio.NewReader(io.LimitReader(r, 8192))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		if strings.HasPrefix(line, "SSH-") {
			return strings.HasPrefix(line, "SSH-2.0-") || strings.HasPrefix(line, "SSH-1.99-")
		}
	}
}

func temporaryReady() Check {
	return Check{Ready: true, Closed: true, Message: "本机 22 端口已关闭，临时 SSH 配置检查通过。批准并建立直连后，打开终端时按需启动。"}
}

func configProblem(detail string) Check {
	return Check{Message: "本机 OpenSSH 配置未通过检查。", Detail: fmt.Sprintf("%s\n可由本机管理员修正后重新检查，或选择已有 SSH 服务的端口。", strings.TrimSpace(detail))}
}
