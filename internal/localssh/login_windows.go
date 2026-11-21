package localssh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/sys/windows"
)

func windowsLoginAccount() (string, string, error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return "", "", errors.New("管理员窗口使用系统 SSH 认证")
	}
	u, err := user.Current()
	if err != nil {
		return "", "", err
	}
	host, err := os.Hostname()
	if err != nil {
		return "", "", err
	}
	domain, name, ok := strings.Cut(u.Username, `\`)
	if !ok || !strings.EqualFold(domain, host) || name == "" || strings.ContainsFunc(name, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("_.-", r)
	}) || strings.ContainsAny(u.HomeDir, "%\"\r\n") {
		return "", "", errors.New("此 Windows 账号使用系统 SSH 认证")
	}
	return strings.ToLower(name), u.HomeDir, nil
}

func PrepareLogin(ctx context.Context) (*Login, error) {
	name, home, err := windowsLoginAccount()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(home, ".peertty-session-")
	if err != nil {
		return nil, err
	}
	s := &Login{User: name, dir: dir}
	s.HostKey, err = NewLoginKey(filepath.Join(dir, "host.key"))
	if err == nil {
		config, stop := context.WithTimeout(ctx, startupTimeout)
		defer stop()
		_, err = windowsLoginArgs(config, dir, 22)
	}
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

func closedLoginGuard(exe, ms string) *exec.Cmd { return guardCmd(exe, ms) }

func windowsLoginArgs(ctx context.Context, dir string, port int) ([]string, error) {
	name, home, err := windowsLoginAccount()
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(filepath.Dir(dir), home) || filepath.Clean(dir) != dir || !strings.HasPrefix(filepath.Base(dir), ".peertty-session-") {
		return nil, errors.New("无效的本次登录目录")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(system, "OpenSSH", "sshd.exe")
	match := func(p int) string {
		return fmt.Sprintf("user=%s,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=%d", name, p)
	}
	base := func(p int) ([]byte, error) {
		return exec.CommandContext(ctx, path, "-T", "-h", filepath.Join(dir, "host.key"), "-C", match(p)).Output()
	}
	original, err := base(22)
	if err != nil {
		return nil, fmt.Errorf("无法读取 Windows OpenSSH 账号策略: %w", err)
	}
	if err = checkUserKeyPolicy(original); err != nil {
		return nil, err
	}
	if port != 22 {
		actual, e := base(port)
		if e != nil || string(actual) != string(original) {
			return nil, errors.New("本机 SSH 端口策略需要系统认证")
		}
	}
	args := append(windowsListenArgs(port), loginArgs(dir)...)
	config, err := exec.CommandContext(ctx, path, append([]string{"-T", "-C", match(port)}, args...)...).Output()
	if err != nil {
		return nil, err
	}
	if err = checkLoginPolicy(config, dir); err != nil {
		return nil, err
	}
	if err = checkWindowsLoopback(config, port); err != nil {
		return nil, err
	}
	return args, nil
}
