//go:build linux || darwin

package localssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var accountName = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)

// PrepareLogin runs as the local approver. The private directory is under
// their actual home so OpenSSH StrictModes can verify all parent directories.
func PrepareLogin(ctx context.Context) (*Login, error) {
	account, err := user.Current()
	if err != nil {
		return nil, err
	}
	if os.Geteuid() == 0 || !accountName.MatchString(account.Username) {
		return nil, errors.New("此账号使用系统 SSH 登录")
	}
	if strings.ContainsAny(account.HomeDir, "%\"\\\r\n") {
		return nil, errors.New("此主目录需要系统 SSH 登录")
	}
	dir, err := os.MkdirTemp(account.HomeDir, ".peertty-session-")
	if err != nil {
		return nil, err
	}
	s := &Login{User: account.Username, dir: dir}
	s.HostKey, err = NewLoginKey(filepath.Join(dir, "host.key"))
	if err == nil {
		probe, cancel := context.WithTimeout(ctx, startupTimeout)
		defer cancel()
		err = verifyLoginSSHD(probe, dir, account.Username, nil, 22)
	}
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

// Root may bind 22 for a normal user. It never starts sshd with root rights
// and never opens any key or configuration path supplied by that user.
func loginOwner(dir string) (*user.User, *syscall.Credential, error) {
	account, err := user.Current()
	if os.Geteuid() == 0 {
		uid := os.Getenv("SUDO_UID")
		if uid == "" || uid == "0" {
			return nil, nil, errors.New("本次登录需要普通账号在本机批准")
		}
		account, err = user.LookupId(uid)
	}
	if err != nil {
		return nil, nil, err
	}
	if account.Uid == "0" || !accountName.MatchString(account.Username) ||
		filepath.Clean(dir) != dir || filepath.Dir(dir) != account.HomeDir ||
		!strings.HasPrefix(filepath.Base(dir), ".peertty-session-") {
		return nil, nil, errors.New("本次登录目录不属于批准账号")
	}
	if os.Geteuid() != 0 {
		return account, nil, nil
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return nil, nil, err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, nil, err
	}
	ids, err := account.GroupIds()
	if err != nil {
		return nil, nil, err
	}
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	for _, id := range ids {
		n, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return nil, nil, err
		}
		cred.Groups = append(cred.Groups, uint32(n))
	}
	return account, cred, nil
}

func loginSSHD(ctx context.Context, dir string, cred *syscall.Credential, mode ...string) *exec.Cmd {
	args := append(mode, loginArgs(dir)...)
	cmd := exec.CommandContext(ctx, sshd, args...)
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	return cmd
}

func verifyLoginSSHD(ctx context.Context, dir, account string, cred *syscall.Credential, port int) error {
	match := func(n int) string {
		return fmt.Sprintf("user=%s,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=%d", account, n)
	}
	base := exec.CommandContext(ctx, sshd, "-T", "-h", filepath.Join(dir, "host.key"), "-C", match(22))
	if cred != nil {
		base.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	var baseDiag bytes.Buffer
	base.Stderr = &baseDiag
	original, err := base.Output()
	if err != nil {
		msg := strings.TrimSpace(baseDiag.String())
		if strings.Contains(strings.ToLower(msg), "permission denied") && strings.Contains(msg, "sshd_config") {
			return errors.New("当前账号无权读取系统 sshd_config，将改用系统 SSH 认证")
		}
		return fmt.Errorf("无法读取本机 SSH 账号策略: %w", err)
	}
	if err = checkUserKeyPolicy(original); err != nil {
		return err
	}
	if port != 22 {
		actual := exec.CommandContext(ctx, sshd, "-T", "-h", filepath.Join(dir, "host.key"), "-C", match(port))
		actual.SysProcAttr = base.SysProcAttr
		rules, err := actual.Output()
		if err != nil || !bytes.Equal(original, rules) {
			return errors.New("本机对不同 SSH 端口设有独立策略，请使用系统 SSH 认证")
		}
	}
	config, err := loginSSHD(ctx, dir, cred, "-T", "-C", match(port)).Output()
	if err != nil {
		return fmt.Errorf("OpenSSH 无法启用本次账号公钥登录: %w", err)
	}
	return checkLoginPolicy(config, dir)
}

func closedLoginGuard(exe, ms string) *exec.Cmd {
	if err := probeBind22(); errors.Is(err, os.ErrPermission) {
		return guardCmd(exe, ms)
	}
	return exec.Command(exe, GuardCommand, ms)
}
