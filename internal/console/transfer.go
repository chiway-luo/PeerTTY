package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"peertty/internal/active"
	"peertty/internal/localssh"
)

func resolveTransferGrant(ctx context.Context, key string, diag io.Writer) (active.State, error) {
	status := func(ctx context.Context) (active.State, error) { return active.Status(ctx, key) }
	return resolveTransferGrantWith(ctx, diag, status,
		func(ctx context.Context, s active.State, diag io.Writer) (active.State, error) {
			tick := time.NewTicker(300 * time.Millisecond)
			defer tick.Stop()
			return waitReconnect(ctx, s, diag, tick.C, status)
		})
}

func resolveTransferGrantWith(ctx context.Context, diag io.Writer,
	status func(context.Context) (active.State, error),
	wait func(context.Context, active.State, io.Writer) (active.State, error),
) (active.State, error) {
	s, err := status(ctx)
	if err != nil {
		return active.State{}, err
	}
	if s.OneShot {
		return active.State{}, active.ErrOneShot
	}
	if s.Role == "control" && s.Phase == "disconnected" {
		if terminalFile(diag) {
			fmt.Fprintln(diag, reconnectRevokeHint)
		}
		s, err = wait(ctx, s, diag)
		if err != nil {
			return active.State{}, err
		}
	}
	if s.Role != "control" || s.Phase != "ready" {
		if s.Phase == "offline" {
			return active.State{}, fmt.Errorf("直连已断开，请重新配对 · %s", s.Note)
		}
		return active.State{}, errors.New("本机尚无已连接的控制授权，输入 peertty status 查看状态")
	}
	return s, nil
}

// expandRemoteArg turns ":path" or "remote:path" into "<user>@<alias>:<path>"
// without touching Windows drive paths such as "C:\foo" or local paths.
func expandRemoteArg(arg string, s active.State) (string, bool) {
	target := s.User + "@" + s.Alias
	if strings.HasPrefix(arg, ":") {
		return target + arg, true
	}
	if rest, ok := strings.CutPrefix(arg, "remote:"); ok {
		return target + ":" + rest, true
	}
	return arg, false
}

func scpArgs(exe string, s active.State, recursive bool, paths []string) ([]string, error) {
	if len(paths) < 2 {
		return nil, errors.New("用法: peertty cp [-r] <源路径>... <目标路径>（远端路径用 : 开头，例如 :/var/log/syslog ./）")
	}
	args := sshOptions(exe, "_link-proxy", s)
	if recursive {
		args = append(args, "-r")
	}
	hasRemote := false
	expanded := make([]string, len(paths))
	for i, p := range paths {
		var remote bool
		expanded[i], remote = expandRemoteArg(p, s)
		if remote {
			hasRemote = true
		} else if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ":") && filepath.VolumeName(p) == "" {
			// scp interprets a colon before the first slash as a host separator.
			expanded[i] = "." + string(filepath.Separator) + p
		}
	}
	if !hasRemote {
		return nil, errors.New("请用 : 开头标明远端路径，例如 peertty cp :/etc/hosts ./hosts 或 peertty cp ./a.sh :/tmp/")
	}
	args = append(args, "--")
	return append(args, expanded...), nil
}

func sftpArgs(exe string, s active.State, extra []string) ([]string, error) {
	// OpenSSH accepts grouped flags and attached values. Only forward options
	// that leave the grant's destination, SSH program and credentials intact.
	for i := 0; i < len(extra); i++ {
		flags, option := strings.CutPrefix(extra[i], "-")
		if !option || flags == "" {
			return nil, errors.New("SFTP 目标由当前授权指定")
		}
		if flags == "-" && i == len(extra)-1 {
			extra = extra[:i]
			break
		}
		for j, flag := range flags {
			if strings.ContainsRune("46aCfNpqrv", flag) {
				continue
			}
			if !strings.ContainsRune("BbclRsX", flag) {
				return nil, fmt.Errorf("当前授权不支持 SFTP 选项 -%c", flag)
			}
			if j+1 == len(flags) {
				i++
				if i == len(extra) || extra[i] == "" {
					return nil, fmt.Errorf("SFTP 选项 -%c 缺少参数", flag)
				}
			}
			break // The rest of this argument, or the next argument, is the value.
		}
	}
	args := sshOptions(exe, "_link-proxy", s)
	args = append(args, extra...)
	return append(args, "--", s.User+"@"+s.Alias), nil
}

// Copy transfers files over the active PeerTTY grant using native OpenSSH scp.
// Remote paths are prefixed with ":" (for example ":/var/log/app.log" or "remote:/tmp/file").
func Copy(ctx context.Context, key string, in *os.File, out, diag io.Writer, recursive bool, paths []string) error {
	s, err := resolveTransferGrant(ctx, key, diag)
	if err != nil {
		return err
	}
	return runTransfer(ctx, key, s, in, out, diag, "scp", func(exe string) ([]string, error) {
		return scpArgs(exe, s, recursive, paths)
	}, (*exec.Cmd).Run)
}

// SFTP launches an interactive native OpenSSH sftp session over the active grant.
func SFTP(ctx context.Context, key string, in *os.File, out, diag io.Writer, extra []string) error {
	s, err := resolveTransferGrant(ctx, key, diag)
	if err != nil {
		return err
	}
	return runTransfer(ctx, key, s, in, out, diag, "sftp", func(exe string) ([]string, error) {
		return sftpArgs(exe, s, extra)
	}, (*exec.Cmd).Run)
}

func runTransfer(ctx context.Context, key string, s active.State, in *os.File, out, diag io.Writer, tool string, buildArgs func(exe string) ([]string, error), run func(*exec.Cmd) error) (result error) {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args, err := buildArgs(exe)
	if err != nil {
		return err
	}
	bin, err := localssh.ToolPath(tool)
	if err != nil {
		return fmt.Errorf("未找到本机 OpenSSH %s 工具: %w", tool, err)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, diag
	cmd.Env = append(os.Environ(), programEnv+"="+exe, "PEERTTY_LINK_KEY="+key, "PEERTTY_LINK_ID="+s.ID)
	if in != nil {
		restore, err := keepSSHInput(in)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, restore()) }()
	}
	return run(cmd)
}
