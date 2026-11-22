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
	role, deb, rpm := "客户端", "openssh-client", "openssh-clients"
	note := ""
	if server {
		role, deb, rpm = "服务端", "openssh-server", "openssh-server"
		note = "。发行版安装服务端时可能同时启动系统 SSH 服务"
	}
	msg := "本机缺少 OpenSSH " + role
	if runtime.GOOS == "linux" {
		for _, manager := range []struct{ path, pkg string }{
			{"/usr/bin/apt-get", deb}, {"/usr/bin/dnf", rpm}, {"/usr/bin/yum", rpm},
		} {
			if _, err := exec.LookPath(manager.path); err == nil {
				return adminAction(msg+note+"。", "通过系统软件包管理器安装 OpenSSH "+role, manager.path, "install", manager.pkg)
			}
		}
	}
	return Check{Message: msg + "。", Detail: "请通过本机的系统软件管理工具安装或恢复 OpenSSH " + role + "，然后选择重新检查。"}
}

func checkStopped(ctx context.Context) Check {
	return stoppedCheck{
		stat:        func() error { _, err := os.Stat(sshd); return err },
		euid:        os.Geteuid,
		hasGuard:    func() bool { exe, _ := os.Executable(); return adminGuardPath(exe) != "" },
		bind:        probeBind22,
		checkConfig: checkNativeConfig,
	}.run(ctx)
}

// Keep the decision separate from OS probes so their outcomes can be tested
// without touching the machine's OpenSSH setup, privileges or port 22.
type stoppedCheck struct {
	stat, bind  func() error
	euid        func() int
	hasGuard    func() bool
	checkConfig func(context.Context) (string, error)
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
	return syscall.Bind(fd, &syscall.SockaddrInet4{Port: 22, Addr: [4]byte{127, 0, 0, 1}})
}

func systemInstallRequired() Check {
	check := Check{Message: "本机限制普通程序绑定 22 端口。临时 SSH 需要系统安装版 PeerTTY。"}
	if runtime.GOOS != "darwin" {
		for _, pkg := range []struct{ manager, ext, query string }{
			{"/usr/bin/apt-get", ".deb", "/usr/bin/dpkg-deb"},
			{"/usr/bin/dnf", ".rpm", "/usr/bin/rpm"},
			{"/usr/bin/yum", ".rpm", "/usr/bin/rpm"},
		} {
			if _, err := exec.LookPath(pkg.manager); err != nil {
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
				name, err := exec.CommandContext(ctx, pkg.query, query...).Output()
				if err != nil || strings.TrimSpace(string(name)) != "peertty" {
					return errors.New("这个文件不是可读取的 PeerTTY 安装包")
				}
				return adminAction("", "", pkg.manager, "install", path).Apply(ctx, in, out, "")
			}
			return check
		}
		check.Detail = "请使用本机的软件管理器安装系统版，再重新检查，也可以改用已有 SSH 服务的端口。"
		return check
	}
	check.Action = "选择 PeerTTY 安装包并打开 macOS 安装器"
	check.Detail = "请选择本版 PeerTTY-macOS.pkg。系统安装只添加程序，完成后关闭安装器，菜单会自动复查。"
	check.Apply = func(ctx context.Context, _ *os.File, out io.Writer, _ string) error {
		data, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e",
			`POSIX path of (choose file with prompt "选择 PeerTTY-macOS.pkg" of type {"com.apple.installer-package-archive", "com.apple.installer-package", "com.apple.installer-flat-package"})`).Output()
		if err != nil {
			return err
		}
		pkg := strings.TrimRight(string(data), "\r\n")
		if !filepath.IsAbs(pkg) || !strings.EqualFold(filepath.Ext(pkg), ".pkg") {
			return errors.New("请选择本地的 PeerTTY macOS 安装包")
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/open", "-W", "-n", "-b", "com.apple.installer", pkg)
		cmd.Stdout, cmd.Stderr = out, out
		return cmd.Run()
	}
	return check
}

func unixConfigProblem(log string) Check {
	const runtimeDir = "/run/sshd"
	switch {
	case strings.Contains(log, "no hostkeys available"):
		return adminAction("OpenSSH 缺少可用的主机密钥。", "生成缺失的系统默认 SSH 主机密钥", "/usr/bin/ssh-keygen", "-A")
	case runtime.GOOS == "linux" && (strings.HasSuffix(log, "Missing privilege separation directory: /run/sshd") ||
		strings.HasSuffix(log, "Missing privilege separation directory: /var/run/sshd")):
		return adminAction("OpenSSH 缺少系统运行目录。", "创建 /run/sshd 运行目录", "/usr/bin/mkdir", "-m", "0755", "--", runtimeDir)
	case strings.Contains(log, "not in the sudoers") || strings.Contains(log, "not allowed to execute"):
		return Check{Message: "本机账号没有准备临时 SSH 的管理员权限。", Detail: "可请本机管理员操作，或选择已有 SSH 服务的端口。"}
	case os.Geteuid() != 0 && strings.Contains(log, "sudo:"):
		return systemAction("本机 22 端口已关闭，检查临时 OpenSSH 需要本机管理员授权。",
			"使用系统提示验证管理员权限", "/usr/bin/sudo", "-v")
	default:
		return configProblem(log)
	}
}
