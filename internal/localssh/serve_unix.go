//go:build darwin || linux

package localssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

const refused = syscall.ECONNREFUSED
const sshd = "/usr/sbin/sshd"

// Only ask sudo to execute PeerTTY when the executable and its entire resolved
// path are administrator-controlled. A portable user-writable build runs as-is.
func guardCmd(exe, deadline string) *exec.Cmd {
	if os.Geteuid() != 0 {
		if path := adminGuardPath(exe); path != "" {
			return exec.Command("/usr/bin/sudo", "-n", "--", path, GuardCommand, deadline)
		}
	}
	return exec.Command(exe, GuardCommand, deadline)
}

func adminGuardPath(exe string) string {
	installed := "/usr/bin/peertty"
	if runtime.GOOS == "darwin" {
		installed = "/Library/PeerTTY/peertty"
	}
	for _, candidate := range []string{exe, installed} {
		path, err := filepath.EvalSymlinks(candidate)
		if err == nil && filepath.IsAbs(path) && adminOwned(path) {
			info, err := os.Stat(path)
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				return path
			}
		}
	}
	return ""
}

func adminOwned(path string) bool {
	for {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm()&0022 != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		parent := filepath.Dir(path)
		if parent == path {
			return true
		}
		path = parent
	}
}

func nativeSSHD(ctx context.Context, mode string) *exec.Cmd {
	args := []string{mode, "-o", "DisableForwarding=yes", "-o", "MaxSessions=1"}
	if os.Geteuid() != 0 {
		args = append([]string{"-n", "--", sshd}, args...)
		return exec.CommandContext(ctx, "/usr/bin/sudo", args...)
	}
	return exec.CommandContext(ctx, sshd, args...)
}

func serveLocal(ctx context.Context, ports <-chan int, out io.Writer, mode, dir string) error {
	if _, err := os.Stat(sshd); err != nil {
		return fmt.Errorf("请在被控机安装并初始化 OpenSSH Server: %w", err)
	}
	lc := net.ListenConfig{}
	addr := "127.0.0.1:22"
	if mode == "login-open" {
		addr = "127.0.0.1:0"
	}
	listener, err := lc.Listen(ctx, "tcp4", addr)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("当前程序无权绑定回环 22 端口，请在主菜单选 5 准备本机或选择已有 SSH 服务的端口: %w", err)
		}
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	start, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	server := nativeSSHD(ctx, "-i")
	if mode != "" {
		account, cred, err := loginOwner(dir)
		if err != nil {
			return err
		}
		// Also evaluate the real destination port for Match LocalPort rules.
		if err := verifyLoginSSHD(start, dir, account.Username, cred, listener.Addr().(*net.TCPAddr).Port); err != nil {
			return err
		}
		server = loginSSHD(ctx, dir, cred, "-i", "-e")
	} else {
		check := nativeSSHD(start, "-t")
		if msg, err := check.CombinedOutput(); err != nil {
			return fmt.Errorf("请核对被控机的 OpenSSH Server 配置、主机密钥与本机管理员权限: %w", cmdError(check, err, string(msg)))
		}
	}
	ready := "READY"
	if mode == "login-open" {
		ready = fmt.Sprintf("READY %d", listener.Addr().(*net.TCPAddr).Port)
	}
	port, err := peerPort(start, ports, out, ready)
	if err != nil {
		return err
	}
	ln := listener.(*net.TCPListener)
	until, _ := start.Deadline()
	if err := ln.SetDeadline(until); err != nil {
		return err
	}
	var socket *os.File
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return err
		}
		remote := conn.RemoteAddr().(*net.TCPAddr)
		if remote.Port != port || !remote.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			conn.Close()
			continue
		}
		socket, err = conn.File()
		conn.Close()
		if err != nil {
			return err
		}
		break
	}
	// inetd mode receives exactly this already-connected socket. No second
	// local client can reach the temporary OpenSSH server.
	ln.Close()
	server.Stdin, server.Stdout, server.Stderr = socket, socket, os.Stderr
	if err := server.Start(); err != nil {
		socket.Close()
		return err
	}
	socket.Close()
	if _, err := fmt.Fprintln(out, "ATTACHED"); err != nil {
		server.Process.Kill()
		server.Wait()
		return err
	}
	err = server.Wait()
	if ctx.Err() != nil {
		return nil
	}
	// Per-connection sshd also exits 255 for an ordinary SSH_MSG_DISCONNECT.
	// The parent checks the banner and native ssh delivers the login/exit
	// status to the operator. The guard reports failure to start or reap.
	var exited *exec.ExitError
	if errors.As(err, &exited) && exited.ExitCode() == 255 {
		return nil
	}
	return err
}
