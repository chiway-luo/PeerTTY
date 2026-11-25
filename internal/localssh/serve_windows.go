package localssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const refused = windows.WSAECONNREFUSED

var tcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
var isProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// MIB_TCPTABLE_OWNER_PID has a DWORD count followed by six DWORDs per IPv4 row.
// Report ready only when the kernel attributes the loopback listener to our child.
func ownsListener(pid, port int) (bool, error) {
	const listenersWithPID = 3
	size := uint32(4096)
	for {
		table := make([]byte, size)
		code, _, _ := tcpTable.Call(uintptr(unsafe.Pointer(&table[0])), uintptr(unsafe.Pointer(&size)),
			0, windows.AF_INET, listenersWithPID, 0)
		if syscall.Errno(code) == windows.ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		if code != 0 {
			return false, syscall.Errno(code)
		}
		if size < 4 || size > uint32(len(table)) {
			return false, errors.New("无效的 Windows TCP 监听表")
		}
		count := binary.LittleEndian.Uint32(table[:4])
		const rowSize = 24
		if count > (size-4)/rowSize {
			return false, errors.New("Windows TCP 监听表不完整")
		}
		owned := false
		for i := uint32(0); i < count; i++ {
			row := table[4+i*rowSize : 4+(i+1)*rowSize]
			if binary.LittleEndian.Uint32(row[20:24]) == uint32(pid) {
				if binary.BigEndian.Uint32(row[4:8]) != 0x7f000001 || int(binary.BigEndian.Uint16(row[8:10])) != port {
					return false, errors.New("临时 OpenSSH 监听地址不符合授权范围")
				}
				owned = true
			}
		}
		return owned, nil
	}
}

// ownsClientConnection verifies via GetExtendedTcpTable that the temporary sshd
// process has an active loopback connection from the exact parent client port,
// and no unexpected local peer is attached to it.
func ownsClientConnection(job windows.Handle, pid, localPort, clientPort int) (bool, error) {
	const connectionsWithPID = 4
	size := uint32(4096)
	for {
		table := make([]byte, size)
		code, _, _ := tcpTable.Call(uintptr(unsafe.Pointer(&table[0])), uintptr(unsafe.Pointer(&size)),
			0, windows.AF_INET, connectionsWithPID, 0)
		if syscall.Errno(code) == windows.ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		if code != 0 {
			return false, syscall.Errno(code)
		}
		if size < 4 || size > uint32(len(table)) {
			return false, errors.New("无效的 Windows TCP 连接表")
		}
		count := binary.LittleEndian.Uint32(table[:4])
		const rowSize = 24
		if count > (size-4)/rowSize {
			return false, errors.New("Windows TCP 连接表不完整")
		}
		matched := false
		for i := uint32(0); i < count; i++ {
			row := table[4+i*rowSize : 4+(i+1)*rowSize]
			owner := binary.LittleEndian.Uint32(row[20:24])
			laddr := binary.BigEndian.Uint32(row[4:8])
			lport := int(binary.BigEndian.Uint16(row[8:10]))
			if owner != uint32(pid) {
				// Some OpenSSH builds hand the socket to a session child.
				if owner == 0 || owner == uint32(os.Getpid()) || laddr != 0x7f000001 || lport != localPort {
					continue
				}
				member, err := processInGuardJob(owner, job)
				if err != nil {
					return false, err
				}
				if !member {
					continue
				}
			}
			raddr := binary.BigEndian.Uint32(row[12:16])
			rport := int(binary.BigEndian.Uint16(row[16:18]))
			if laddr != 0x7f000001 || lport != localPort || raddr != 0x7f000001 || rport != clientPort {
				return false, errors.New("检测到未授权的本机连接接入临时 OpenSSH")
			}
			// MIB_TCP_STATE_ESTAB. A closing socket is no longer attachable.
			if binary.LittleEndian.Uint32(row[:4]) == 5 {
				matched = true
			}
		}
		return matched, nil
	}
}

func processInGuardJob(pid uint32, job windows.Handle) (bool, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(process)
	var member int32
	ok, _, err := isProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&member)))
	if ok == 0 {
		return false, err
	}
	return member != 0, nil
}

// The detached grant worker has no console to inherit. Set the flag on both
// the guard and each native sshd invocation, including configuration probes.
func backgroundCommand(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

func guardCmd(exe, deadline string) *exec.Cmd {
	return backgroundCommand(context.Background(), exe, GuardCommand, deadline)
}

// The guard is a dedicated subprocess. Its non-inheritable job handle lives
// until process exit, when Windows also terminates any remaining sshd children.
func ownProcessTree() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, windows.CurrentProcess())
	}
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func windowsListenArgs(port int) []string {
	n := strconv.Itoa(port)
	return []string{"-4", "-p", n, "-o", "ListenAddress=127.0.0.1:" + n}
}

func windowsSSHDArgs() []string {
	return []string{"-4", "-p", "22", "-o", "ListenAddress=127.0.0.1:22", "-o", "PidFile=none",
		"-o", "MaxSessions=1", "-o", "MaxStartups=1:100:1", "-o", "DisableForwarding=yes"}
}

func checkWindowsConfig(ctx context.Context, path string) error {
	// ListenAddress is additive. Keep the system's account and Match policy,
	// and refuse to launch if it also requests a network-facing listener.
	check := backgroundCommand(ctx, path, append([]string{"-T"}, windowsSSHDArgs()...)...)
	var diag bytes.Buffer
	check.Stderr = &diag
	config, err := check.Output()
	if err != nil {
		return fmt.Errorf("请以本机管理员权限运行，并核对 OpenSSH Server 配置和主机密钥: %w", cmdError(check, err, diag.String()))
	}
	return checkWindowsLoopback(config, 22)
}

func checkWindowsLoopback(config []byte, port int) error {
	want := "127.0.0.1:" + strconv.Itoa(port)
	loopback := false
	for _, line := range strings.Split(string(config), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], "listenaddress") {
			if len(fields) != 2 || fields[1] != want {
				return errors.New("系统 OpenSSH 配置要求监听其他地址，无法启动仅回环的临时实例")
			}
			loopback = true
		}
	}
	if !loopback {
		return errors.New("无法核验临时 OpenSSH 的回环监听地址")
	}
	return nil
}

func serveLocal(ctx context.Context, ports <-chan int, out io.Writer, mode, dir string) error {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(system, "OpenSSH", "sshd.exe")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("请安装并初始化 Windows OpenSSH Server: %w", err)
	}
	job, err := ownProcessTree()
	if err != nil {
		return fmt.Errorf("创建临时 OpenSSH 进程组: %w", err)
	}
	attempts := 1
	if mode == "login-open" {
		attempts = 5
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		port := 22
		ready := "READY"
		args := windowsSSHDArgs()
		if mode != "" {
			if mode == "login-open" {
				l, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					return err
				}
				port = l.Addr().(*net.TCPAddr).Port
				l.Close()
				ready = fmt.Sprintf("READY %d", port)
			}
			login, err := windowsLoginArgs(ctx, dir, port)
			if err != nil {
				return err
			}
			args = login
		} else if err := checkWindowsConfig(ctx, path); err != nil {
			return err
		}
		// OpenSSH's single-connection mode closes the listener after accept.
		// Each later authorized terminal owns a separate process and socket.
		err, retry := runWindowsSSHD(ctx, job, path, append([]string{"-d", "-e"}, args...), port, ready, ports, out)
		if !retry {
			return err
		}
		lastErr = err
	}
	return lastErr
}

func runWindowsSSHD(ctx context.Context, job windows.Handle, path string, args []string, port int, ready string, ports <-chan int, out io.Writer) (error, bool) {
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	server := backgroundCommand(run, path, args...)
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		return err, false
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = server.Wait(); close(done) }()
	defer func() { cancel(); <-done }()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	start, finish := context.WithTimeout(ctx, startupTimeout)
	defer finish()
	for {
		select {
		case <-start.Done():
			return start.Err(), false
		case <-done:
			return fmt.Errorf("OpenSSH 在建立连接前退出 (%v)", waitErr), true
		case <-tick.C:
		}
		listening, err := ownsListener(server.Process.Pid, port)
		if err != nil {
			return err, false
		}
		if listening {
			break
		}
	}
	clientPort, err := peerPort(start, ports, out, ready)
	if err != nil {
		return err, false
	}
	// Verify that the attached connection belongs to the parent's exact local port.
	verify, stopVerify := context.WithTimeout(start, 2*time.Second)
	defer stopVerify()
	if err := waitForOwnedConnection(verify, done, tick.C, func() (bool, error) {
		return ownsClientConnection(job, server.Process.Pid, port, clientPort)
	}); err != nil {
		return err, false
	}
	if _, err := fmt.Fprintln(out, "ATTACHED"); err != nil {
		return err, false
	}
	<-done
	if ctx.Err() != nil {
		return nil, false
	}
	return waitErr, false
}
