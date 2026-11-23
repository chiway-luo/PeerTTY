package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"peertty/internal/active"
	"peertty/internal/bridge"
	"peertty/internal/console"
	"peertty/internal/grant"
	"peertty/internal/localssh"
	"peertty/internal/session"
)

// Release builds set version from the project's VERSION file.
var version = "dev"

const usage = `PeerTTY — peer-to-peer direct SSH for Windows, macOS and Linux
  peertty             打开终端菜单，选择控制设备或允许被控制
  peertty --version   显示程序版本
  peertty link        [-t] [-- 远端命令及参数] 打开已授权设备的 SSH 终端，-t 为命令分配交互终端
  peertty cp          [-r] <源路径>... <目标路径> 通过已授权直连传输文件（远端路径以 : 开头，如 :/var/log/syslog ./）
  peertty sftp        [-b 批处理文件] [传输选项...] 通过已授权直连打开 SFTP
  peertty status      显示当前授权、剩余时间和终端数
  peertty revoke      结束本机当前授权及其所有 SSH 终端
  peertty doctor      [-stun auto|none|URL,URL] [-require-mapping]
  peertty menu        [-state-dir DIR | -key DEVICE.key] [-stun stun:host:3478] [-ttl 1h] [-ssh-port 22] [-ssh-config FILE]
  peertty keygen      -out DEVICE.key
  peertty fingerprint -key DEVICE.key
  peertty host        -key HOST.key -peer OPERATOR_FINGERPRINT -offer SESSION.offer [-ttl 10m] [-ssh-port 22] [-stun stun:host:3478]
  peertty connect     -key OPERATOR.key -peer HOST_FINGERPRINT -offer SESSION.offer -answer SESSION.answer [-stun stun:host:3478]

Use connect as an OpenSSH ProxyCommand. Each offer and answer needs a new filename.`

func main() {
	ctx, stop := commandContext(os.Args[1:])
	err := run(ctx, os.Args[1:])
	stop()
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		var exit *exec.ExitError
		if len(os.Args) > 1 && (os.Args[1] == "link" || os.Args[1] == "cp" || os.Args[1] == "sftp") && errors.As(err, &exit) && exit.ExitCode() > 0 {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "peertty:", err)
		os.Exit(1)
	}
}

func commandContext(args []string) (context.Context, func()) {
	if len(args) == 0 || (args[0] != "connect" && args[0] != "_menu-proxy" && args[0] != "_link-proxy") {
		return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(parent)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		}
		// OpenSSH sends SIGHUP to its ProxyCommand at normal exit. Its pipes
		// are closing; give the bridge a bounded window to deliver FIN/ACK.
		timer := time.NewTimer(bridge.ProxyDrainTimeout)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			cancel()
		}
	}()
	return ctx, func() { signal.Stop(hup); cancel(); stop() }
}

// The leading PeerTTY identity flags belong to this process. From the first
// native option onward, preserve sftp's arguments, including their values.
func sftpOptions(args []string) (identity, native []string) {
	for i := 0; i < len(args); {
		if args[i] == "--" {
			return args[:i], args[i+1:]
		}
		name, _, assigned := strings.Cut(args[i], "=")
		switch name {
		case "-key", "--key", "-state-dir", "--state-dir":
			i++
			if !assigned && i < len(args) {
				i++
			}
		case "-h", "--help":
			return args[:i+1], nil
		default:
			return args[:i], args[i:]
		}
	}
	return args, nil
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		args = []string{"menu"}
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stdout, usage)
		return nil
	}
	if args[0] == "--version" || args[0] == "version" {
		if len(args) != 1 {
			return errors.New("版本查询不接受其他参数")
		}
		fmt.Fprintln(os.Stdout, "PeerTTY", version)
		return nil
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	parse := func() error {
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		return nil
	}
	switch args[0] {
	case active.Command:
		return active.Main(ctx)
	case "_link-proxy":
		return console.LinkProxy(ctx, os.Stdin, os.Stdout)
	case "link", "cp", "sftp", "status", "revoke":
		dir := fs.String("state-dir", "", "设备身份目录")
		key := fs.String("key", "", "已有设备密钥")
		var remote console.RemoteCommand
		var recursive bool
		if args[0] == "link" {
			fs.BoolVar(&remote.TTY, "t", false, "为远端命令分配终端，例如交互式 sudo")
		}
		if args[0] == "cp" {
			fs.BoolVar(&recursive, "r", false, "递归传输目录")
		}
		flags := args[1:]
		var native []string
		if args[0] == "sftp" {
			flags, native = sftpOptions(flags)
		}
		if err := fs.Parse(flags); err != nil {
			return err
		}
		path, err := console.IdentityPath(*dir, *key)
		if err != nil {
			return err
		}
		switch args[0] {
		case "link":
			remote.Args = fs.Args()
			return console.Link(ctx, path, os.Stdin, os.Stdout, os.Stderr, remote)
		case "cp":
			return console.Copy(ctx, path, os.Stdin, os.Stdout, os.Stderr, recursive, fs.Args())
		case "sftp":
			return console.SFTP(ctx, path, os.Stdin, os.Stdout, os.Stderr, native)
		}
		if fs.NArg() != 0 {
			return errors.New("状态与撤销命令不接受额外参数")
		}
		if args[0] == "status" {
			return console.DisplayStatus(ctx, path, os.Stdout)
		}
		return console.EndGrant(ctx, path, os.Stdout)
	case localssh.GuardCommand:
		return localssh.Serve(ctx, args[1:], os.Stdin, os.Stdout)
	case "menu":
		opts := console.Settings{Version: version}
		fs.StringVar(&opts.StateDir, "state-dir", "", "用户私有的设备身份目录")
		fs.StringVar(&opts.KeyPath, "key", "", "使用已有设备密钥")
		fs.StringVar(&opts.STUN, "stun", "auto", "auto 使用默认 STUN，可指定逗号分隔的地址或 none")
		fs.StringVar(&opts.SSHConfig, "ssh-config", "", "控制端的 OpenSSH 配置文件")
		fs.IntVar(&opts.SSHPort, "ssh-port", 22, "被控端回环 SSH 端口")
		fs.DurationVar(&opts.TTL, "ttl", time.Hour, "默认授权时长")
		fs.BoolVar(&opts.NoClipboard, "no-clipboard", false, "关闭本次运行的凭证自动复制")
		if err := parse(); err != nil {
			return err
		}
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "stun":
				opts.ExplicitSTUN = true
			case "ssh-port":
				opts.ExplicitSSHPort = true
			case "ttl":
				opts.ExplicitTTL = true
			case "no-clipboard":
				opts.ExplicitNoClipboard = true
			}
		})
		if opts.StateDir != "" && opts.KeyPath != "" {
			return errors.New("-state-dir 和 -key 请选择一个")
		}
		err := console.Run(ctx, opts, os.Stdin, os.Stdout)
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case "doctor":
		stun := fs.String("stun", "auto", "auto 使用默认 STUN，可指定逗号分隔的地址或 none")
		require := fs.Bool("require-mapping", false, "未取得 STUN 映射时返回退出码 1")
		if err := parse(); err != nil {
			return err
		}
		return console.NetworkCheck(ctx, os.Stdout, *stun, *require)
	case "_menu-proxy":
		return console.RunProxy(ctx, stdio{os.Stdin, os.Stdout}, os.Stderr)
	case "keygen":
		out := fs.String("out", "", "new private key file")
		if err := parse(); err != nil {
			return err
		}
		if *out == "" {
			return errors.New("missing -out")
		}
		fp, err := grant.NewIdentity(*out)
		if err == nil {
			fmt.Fprintln(os.Stdout, fp)
		}
		return err
	case "fingerprint":
		path := fs.String("key", "", "device private key file")
		if err := parse(); err != nil {
			return err
		}
		if *path == "" {
			return errors.New("missing -key")
		}
		key, err := grant.LoadIdentity(*path)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, grant.Fingerprint(key.Public().(ed25519.PublicKey)))
		return nil
	case "host", "connect":
		return runSession(ctx, args[0], fs, parse)
	default:
		return fmt.Errorf("unknown command %q; use peertty help", args[0])
	}
}

func runSession(ctx context.Context, command string, fs *flag.FlagSet, parse func() error) error {
	var opts session.HostOptions
	opts.Status = os.Stderr
	keyPath := fs.String("key", "", "local private key file")
	fs.StringVar(&opts.Peer, "peer", "", "expected peer fingerprint")
	fs.StringVar(&opts.OfferPath, "offer", "", "signed offer file")
	fs.StringVar(&opts.STUN, "stun", "auto", "STUN discovery: auto, none, or comma-separated STUN URLs")
	var answer string
	if command == "host" {
		fs.DurationVar(&opts.TTL, "ttl", 10*time.Minute, "grant duration, including pairing")
		fs.IntVar(&opts.SSHPort, "ssh-port", 22, "local loopback SSH service port")
	} else {
		fs.StringVar(&answer, "answer", "", "new signed answer file")
	}
	if err := parse(); err != nil {
		return err
	}
	if *keyPath == "" || opts.OfferPath == "" || !grant.ValidFingerprint(opts.Peer) {
		return errors.New("provide -key, -offer and the full -peer fingerprint")
	}
	key, err := grant.LoadIdentity(*keyPath)
	if err != nil {
		return err
	}
	opts.Key = key
	lease, err := grant.LeaseIdentity(*keyPath)
	if err != nil {
		return err
	}
	defer lease.Close()
	if command == "host" {
		opts.Approval = approval
		return session.Host(ctx, opts)
	}
	if answer == "" {
		return errors.New("missing -answer")
	}
	return session.Connect(ctx, opts.Options, answer, stdio{os.Stdin, os.Stdout})
}

func approval(ctx context.Context) (string, error) {
	fmt.Fprintln(os.Stderr, "To grant this session, enter the returned answer file path (Enter cancels):")
	type input struct {
		path string
		err  error
	}
	reply := make(chan input, 1)
	go func() {
		scan := bufio.NewScanner(os.Stdin)
		if scan.Scan() {
			reply <- input{path: strings.TrimSpace(scan.Text())}
		} else {
			reply <- input{err: scan.Err()}
		}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-reply:
		if r.err == nil && r.path == "" {
			return "", errors.New("session declined")
		}
		return r.path, r.err
	}
}

type stdio struct{ in, out *os.File }

func (s stdio) Read(b []byte) (int, error)  { return s.in.Read(b) }
func (s stdio) Write(b []byte) (int, error) { return s.out.Write(b) }
func (s stdio) CloseWrite() error           { return s.out.Close() }
func (s stdio) Close() error {
	return errors.Join(s.in.Close(), s.out.Close())
}
