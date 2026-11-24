//go:build darwin || linux

package localssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

func systemTool(name string) (string, error) { return exec.LookPath(filepath.Join("/usr/bin", name)) }

func adminAction(message, label, path string, args ...string) Check {
	if os.Geteuid() != 0 {
		args = append([]string{"--", path}, args...)
		path = "/usr/bin/sudo"
	}
	return systemAction(message, label, path, args...)
}

func missingOpenSSH(server bool) Check {
	return missingOpenSSHWith(server, runtime.GOOS, exec.LookPath, adminAction)
}

func missingOpenSSHWith(server bool, platform string, lookPath func(string) (string, error), action func(string, string, string, ...string) Check) Check {
	role, deb, rpm := "客户端", "openssh-client", "openssh-clients"
	note := ""
	if server {
		role, deb, rpm = "服务端", "openssh-server", "openssh-server"
		note = "。发行版安装服务端时可能同时启动系统 SSH 服务"
	}
	msg := "本机缺少 OpenSSH " + role
	if platform == "linux" {
		for _, manager := range []struct{ path, pkg string }{
			{"/usr/bin/apt-get", deb}, {"/usr/bin/dnf", rpm}, {"/usr/bin/yum", rpm},
		} {
			if _, err := lookPath(manager.path); err == nil {
				return action(msg+note+"。", "通过系统软件包管理器安装 OpenSSH "+role, manager.path, "install", manager.pkg)
			}
		}
	}
	return Check{Message: msg + "。", Detail: "请通过本机的系统软件管理工具安装或恢复 OpenSSH " + role + "，然后选择重新检查。"}
}

func checkStopped(ctx context.Context) Check {
	p := stoppedCheck{
		stat:        func() error { _, err := os.Stat(sshd); return err },
		euid:        os.Geteuid,
		hasGuard:    func() bool { exe, _ := os.Executable(); return adminGuardPath(exe) != "" },
		bind:        probeBind22,
		checkConfig: checkNativeConfig,
	}
	if runtime.GOOS != "darwin" {
		return p.run(ctx)
	}
	p.checkSession = func(ctx context.Context) error {
		login, err := PrepareLogin(ctx)
		if err != nil {
			return err
		}
		return login.Close()
	}
	return p.run(ctx)
}

// Keep the decision separate from OS probes so their outcomes can be tested
// without touching the machine's OpenSSH setup, privileges or port 22.
type stoppedCheck struct {
	stat, bind   func() error
	euid         func() int
	hasGuard     func() bool
	checkConfig  func(context.Context) (string, error)
	checkSession func(context.Context) error
}

func (p stoppedCheck) run(ctx context.Context) Check {
	if err := p.stat(); errors.Is(err, os.ErrNotExist) {
		return missingOpenSSH(true)
	} else if err != nil {
		return Check{Message: "无法读取本机 OpenSSH 服务端。", Detail: err.Error()}
	}
	if p.euid() != 0 && !p.hasGuard() {
		if err := p.bind(); errors.Is(err, os.ErrPermission) {
			return systemInstallRequired()
		} else if err != nil {
			return Check{Message: "当前无法使用本机回环 22 端口，请重新检查。", Detail: err.Error()}
		}
	}
	probe, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if log, err := p.checkConfig(probe); err != nil {
		if probe.Err() != nil {
			return Check{Message: "本机 OpenSSH 配置检查已中断或超时。"}
		}
		if log == "" {
			log = err.Error()
		}
		// A scoped login uses its own host key and the ordinary account's
		// existing sshd policy. Require its own bind and policy checks.
		if p.checkSession != nil && p.euid() != 0 &&
			(strings.Contains(log, "no hostkeys available") || strings.Contains(log, "a password is required")) &&
			p.bind() == nil {
			if err := p.checkSession(probe); err == nil {
				return Check{Ready: true, Closed: true, ScopedOnly: true, Message: "本机 22 端口已关闭，本次授权账号的临时 SSH 配置检查通过。"}
			}
		}
		return unixConfigProblem(log)
	}
	return temporaryReady()
}

func checkNativeConfig(ctx context.Context) (string, error) {
	cmd := nativeSSHD(ctx, "-t")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var detail diagnosticTail
	cmd.Stdout, cmd.Stderr = &detail, &detail
	err := cmd.Run()
	return strings.TrimSpace(string(detail)), err
}

// bind without listen: test this user's low-port permission without accepting a
// connection, starting a daemon or changing any OS network settings.
func probeBind22() error {
	return bindLoopback(22, false)
}

func bindLoopback(port int, reuse bool) error {
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if reuse {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			return err
		}
	}
	return syscall.Bind(fd, &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
}

func systemInstallRequired() Check {
	return systemInstallRequiredWith(runtime.GOOS, exec.LookPath,
		func(ctx context.Context, path string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, path, args...).Output()
		}, adminAction,
		func(ctx context.Context, out io.Writer, path string, args ...string) error {
			cmd := exec.CommandContext(ctx, path, args...)
			cmd.Stdout, cmd.Stderr = out, out
			return cmd.Run()
		})
}

func systemInstallRequiredWith(platform string, lookPath func(string) (string, error), output func(context.Context, string, ...string) ([]byte, error),
	action func(string, string, string, ...string) Check, run func(context.Context, io.Writer, string, ...string) error) Check {
	check := Check{Message: "本机限制普通程序绑定 22 端口。临时 SSH 需要系统安装版 PeerTTY。"}
	if platform != "darwin" {
		for _, pkg := range []struct{ manager, ext, query string }{
			{"/usr/bin/apt-get", ".deb", "/usr/bin/dpkg-deb"},
			{"/usr/bin/dnf", ".rpm", "/usr/bin/rpm"},
			{"/usr/bin/yum", ".rpm", "/usr/bin/rpm"},
		} {
			if _, err := lookPath(pkg.manager); err != nil {
				continue
			}
			check.Action = "从本地 " + pkg.ext + " 安装系统版 PeerTTY"
			check.PackageExt = pkg.ext
			check.Apply = func(ctx context.Context, in *os.File, out io.Writer, path string) error {
				if !filepath.IsAbs(path) || filepath.Ext(path) != pkg.ext {
					return fmt.Errorf("请选择本机的 PeerTTY %s 安装包", pkg.ext)
				}
				query := []string{"-f", path, "Package"}
				if pkg.ext == ".rpm" {
					query = []string{"-qp", "--queryformat", "%{NAME}", path}
				}
				name, err := output(ctx, pkg.query, query...)
				if err != nil || strings.TrimSpace(string(name)) != "peertty" {
					return errors.New("这个文件不是可读取的 PeerTTY 安装包")
				}
				return action("", "", pkg.manager, "install", path).Apply(ctx, in, out, "")
			}
			return check
		}
		check.Detail = "请使用本机的软件管理器安装系统版，再重新检查，也可以改用已有 SSH 服务的端口。"
		return check
	}
	check.Action = "选择 PeerTTY 安装包并打开 macOS 安装器"
	check.Detail = "请选择本版 PeerTTY-macOS.pkg。系统安装只添加程序，完成后关闭安装器，菜单会自动复查。"
	check.Apply = func(ctx context.Context, _ *os.File, out io.Writer, _ string) error {
		data, err := output(ctx, "/usr/bin/osascript", "-e",
			`POSIX path of (choose file with prompt "选择 PeerTTY-macOS.pkg" of type {"com.apple.installer-package-archive", "com.apple.installer-package", "com.apple.installer-flat-package"})`)
		if err != nil {
			return err
		}
		pkg := strings.TrimRight(string(data), "\r\n")
		if !filepath.IsAbs(pkg) || !strings.EqualFold(filepath.Ext(pkg), ".pkg") {
			return errors.New("请选择本地的 PeerTTY macOS 安装包")
		}
		return run(ctx, out, "/usr/bin/open", "-W", "-n", "-b", "com.apple.installer", pkg)
	}
	return check
}

func unixConfigProblem(log string) Check {
	return unixConfigProblemFor(log, runtime.GOOS, os.Geteuid(), adminAction)
}

func unixConfigProblemFor(log, platform string, uid int, action func(string, string, string, ...string) Check) Check {
	const runtimeDir = "/run/sshd"
	switch {
	case strings.Contains(log, "no hostkeys available"):
		if platform == "darwin" {
			return Check{Message: "本机 22 端口已关闭，系统 SSH 当前没有可用的主机密钥。"}
		}
		return action("OpenSSH 缺少可用的主机密钥。", "生成缺失的系统默认 SSH 主机密钥", "/usr/bin/ssh-keygen", "-A")
	case platform == "linux" && (strings.HasSuffix(log, "Missing privilege separation directory: /run/sshd") ||
		strings.HasSuffix(log, "Missing privilege separation directory: /var/run/sshd")):
		return action("OpenSSH 缺少系统运行目录。", "创建 /run/sshd 运行目录", "/usr/bin/mkdir", "-m", "0755", "--", runtimeDir)
	case strings.Contains(log, "not in the sudoers") || strings.Contains(log, "not allowed to execute"):
		return Check{Message: "本机账号没有准备临时 SSH 的管理员权限。", Detail: "可请本机管理员操作，或选择已有 SSH 服务的端口。"}
	case uid != 0 && strings.Contains(log, "sudo:"):
		return systemAction("本机 22 端口已关闭，检查临时 OpenSSH 需要本机管理员授权。",
			"使用系统提示验证管理员权限", "/usr/bin/sudo", "-v")
	default:
		return configProblem(log)
	}
}
