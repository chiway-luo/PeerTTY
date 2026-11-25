package localssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"peertty/internal/grant"
)

// Login holds the host key for exactly one invitation, before a controller is known.
type Login struct {
	User    string
	HostKey ed25519.PublicKey
	dir     string
}

// NewLoginKey writes an OpenSSH-format private key inside a caller-owned
// private directory. Only the returned public half travels in a signed ticket.
func NewLoginKey(path string) (ed25519.PublicKey, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return nil, err
	}
	f, err := createLoginKeyFile(path)
	if err != nil {
		return nil, err
	}
	writeErr := pem.Encode(f, block)
	return pub, errors.Join(writeErr, f.Close())
}

func publicLine(key ed25519.PublicKey) ([]byte, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("SSH 公钥长度无效")
	}
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(pub), nil
}

func PinLoginHost(path, alias string, key ed25519.PublicKey) error {
	line, err := publicLine(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append([]byte(alias+" "), line...), 0600)
}

func (s *Login) Close() error { return os.RemoveAll(s.dir) }

// Open approves only the selected reply's key. Native sshd reads a private
// per-invitation file; the account's normal authorized_keys is never modified.
func (s *Login) Authorize(key ed25519.PublicKey) error {
	line, err := publicLine(key)
	if err != nil {
		return err
	}
	file := filepath.Join(s.dir, "authorized-"+s.User)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append([]byte("restrict,pty "), line...))
	return errors.Join(err, f.Close())
}

func (s *Login) OpenAuthorized(ctx context.Context) (*Conn, error) {
	if err := grant.CheckLifetime(ctx); err != nil {
		return nil, err
	}
	return openLogin(ctx, s.dir)
}

// OpenSSH expands %u in AuthorizedKeysFile. Binding the filename to the OS
// account prevents the same key from authenticating as a different user.
func loginArgs(dir string) []string {
	authfile := strconv.Quote(filepath.ToSlash(filepath.Join(dir, "authorized-%u")))
	args := []string{"-h", filepath.Join(dir, "host.key"), "-o", "AuthorizedKeysFile=" + authfile, "-o", "TrustedUserCAKeys=none",
		"-o", "PasswordAuthentication=no", "-o", "DisableForwarding=yes", "-o", "MaxSessions=1"}
	if runtime.GOOS != "windows" {
		args = append(args, "-o", "AuthorizedKeysCommand=none", "-o", "KbdInteractiveAuthentication=no",
			"-o", "HostbasedAuthentication=no", "-o", "PermitRootLogin=no", "-o", "PidFile=none")
	}
	return args
}

// Only ordinary accounts already allowed to manage their own public keys can
// delegate a login. Centrally managed keys and multi-factor policies stay native.
func checkUserKeyPolicy(config []byte) error {
	var keys, method, pub, session bool
	for _, line := range strings.Split(string(config), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "authorizedkeysfile":
			for _, path := range strings.Fields(v) {
				if path == ".ssh/authorized_keys" || path == "%h/.ssh/authorized_keys" {
					keys = true
				}
			}
		case "authenticationmethods":
			method = v == "any" || strings.Contains(" "+v+" ", " publickey ")
		case "pubkeyauthentication":
			pub = v == "yes"
		case "maxsessions":
			n, _ := strconv.Atoi(v)
			session = n > 0
		}
	}
	if !keys || !method || !pub || !session {
		return errors.New("本机 SSH 策略要求使用已有的登录凭据")
	}
	return nil
}

func openLogin(ctx context.Context, dir string) (*Conn, error) {
	ms, err := guardDeadline(ctx)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	addr, mode := "127.0.0.1:22", "login-closed"
	existing, err := dial(ctx, addr)
	if err == nil {
		existing.Close()
		mode, addr = "login-open", "127.0.0.1:0"
	} else if !errors.Is(err, refused) {
		return nil, err
	}
	cmd := loginGuard(exe, ms, mode == "login-closed")
	cmd.Args = append(cmd.Args, mode, dir)
	return attach(ctx, addr, cmd)
}

// Match blocks may override some command-line defaults. Only advertise
// single-approval login if the native daemon's effective policy permits it.
func checkLoginPolicy(config []byte, dir string) error {
	want := map[string]string{
		"pubkeyauthentication": "yes", "authorizedkeysfile": filepath.ToSlash(filepath.Join(dir, "authorized-%u")),
		"trustedusercakeys": "none", "disableforwarding": "yes", "passwordauthentication": "no", "maxsessions": "1",
	}
	if runtime.GOOS != "windows" {
		want["authorizedkeyscommand"] = "none"
		want["hostbasedauthentication"] = "no"
		want["kbdinteractiveauthentication"] = "no"
		want["permitrootlogin"] = "no"
	}
	for _, line := range strings.Split(string(config), "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		switch field {
		case "authenticationmethods":
			if value != "any" && !strings.Contains(" "+value+" ", " publickey ") {
				return errors.New("本机 SSH 策略要求其他认证步骤")
			}
		case "gssapiauthentication", "kerberosauthentication", "permitemptypasswords":
			if value != "no" {
				return fmt.Errorf("本机 SSH 策略启用了 %s", field)
			}
		}
		if expected, ok := want[field]; ok {
			if strings.Trim(value, "\"") != expected {
				return fmt.Errorf("本机 SSH 策略不支持本次会话的 %s", field)
			}
			delete(want, field)
		}
	}
	if len(want) != 0 {
		return errors.New("无法确认本机 OpenSSH 的会话认证策略")
	}
	return nil
}
