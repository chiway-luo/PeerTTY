package localssh

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func systemClient() (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	return exec.LookPath(filepath.Join(dir, "OpenSSH", "ssh.exe"))
}

func missingOpenSSH(server bool) Check {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return Check{Message: "无法读取 Windows 系统目录。", Detail: err.Error()}
	}
	role, capability := "客户端", "OpenSSH.Client~~~~0.0.1.0"
	note := ""
	if server {
		role, capability = "服务端", "OpenSSH.Server~~~~0.0.1.0"
		note = "。Windows 安装服务端时可能创建系统防火墙规则"
	}
	message, label := "本机缺少 OpenSSH "+role+note+"。", "使用 Windows 安装 OpenSSH "+role
	if windows.GetCurrentProcessToken().IsElevated() {
		return systemAction(message, label, filepath.Join(dir, "dism.exe"), "/Online", "/Add-Capability", "/CapabilityName:"+capability, "/NoRestart")
	}
	// The only elevated program is Windows' own DISM. The capability names
	// are constants. No terminal input is included in PowerShell source.
	script := "$ErrorActionPreference='Stop'; $d=Join-Path ([Environment]::SystemDirectory) 'dism.exe'; " +
		"$p=Start-Process -FilePath $d -Verb RunAs -Wait -PassThru -ArgumentList '/Online','/Add-Capability','/CapabilityName:" +
		capability + "','/NoRestart'; exit $p.ExitCode"
	return systemAction(message, label, filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
}

func openAdminMenu(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	escaped := make([]string, len(args))
	for i, arg := range args {
		escaped[i] = windows.EscapeArg(arg)
	}
	params, err := windows.UTF16PtrFromString(strings.Join(escaped, " "))
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL)
}

func checkStopped(ctx context.Context) Check {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return Check{Message: "无法读取 Windows 系统目录。", Detail: err.Error()}
	}
	path := filepath.Join(system, "OpenSSH", "sshd.exe")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return missingOpenSSH(true)
	} else if err != nil {
		return Check{Message: "无法读取本机 OpenSSH 服务端。", Detail: err.Error()}
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		if login, err := PrepareLogin(ctx); err == nil {
			if err = login.Close(); err == nil {
				return Check{Ready: true, Message: "本机 22 端口已关闭，可由当前账号按次启动回环 OpenSSH。"}
			}
		}
		return Check{Message: "本机 22 端口已关闭，临时 OpenSSH 需要本机管理员权限。",
			Action: "通过 Windows 授权，在管理员窗口打开 PeerTTY", StartAdmin: openAdminMenu}
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return Check{Message: "无法读取 Windows 的 OpenSSH 配置位置。", Detail: err.Error()}
	}
	if _, err := os.Stat(filepath.Join(programData, "ssh", "sshd_config")); errors.Is(err, os.ErrNotExist) {
		return systemAction("Windows 尚未初始化 OpenSSH 配置。可在系统服务管理器中启动 OpenSSH SSH Server 完成首次初始化，系统服务将按本机配置监听。",
			"打开 Windows 服务管理器", filepath.Join(system, "mmc.exe"), filepath.Join(system, "services.msc"))
	}
	probe, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if err := checkWindowsConfig(probe, path); err != nil {
		if strings.Contains(err.Error(), "no hostkeys available") {
			return systemAction("OpenSSH 缺少可用的主机密钥。", "生成缺失的系统默认 SSH 主机密钥",
				filepath.Join(system, "OpenSSH", "ssh-keygen.exe"), "-A")
		}
		return configProblem(err.Error())
	}
	return temporaryReady()
}
