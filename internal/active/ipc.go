// Package active owns a time-limited grant independently of the terminal UI.
package active

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"peertty/internal/grant"
)

var ErrInactive = errors.New("当前没有有效的 PeerTTY 授权")

type State struct {
	ID, Role, Phase, Device, User, Route, Exchange, Note string
	Deadline                                             time.Time
	Terminals                                            int
	// Local OpenSSH options for the authorized controller, sent only over local mTLS.
	Alias, Identity, KnownHosts, SSHConfig string
}

type request struct {
	Op, ID string
	Answer *grant.Ticket `json:",omitempty"`
}
type reply struct {
	State State
	Error string `json:",omitempty"`
}

// The OS-protected identity authenticates both ends of the loopback socket.
// The rendezvous file contains only a port. Reuse of a stale port confers no access.
func localTLS(key ed25519.PrivateKey) (*tls.Config, error) {
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2120, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		RootCAs: pool, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, ServerName: "localhost"}, nil
}

const frameLimit = 2 * grant.MaxTicketSize

func send(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > frameLimit {
		return errors.New("本机请求过大")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	if _, err = w.Write(size[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
func receive(r io.Reader, v any) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > frameLimit {
		return errors.New("无效的本机请求长度")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func call(ctx context.Context, keyPath string, req request) (*tls.Conn, State, error) {
	var st State
	data, err := os.ReadFile(keyPath + ".active")
	if errors.Is(err, os.ErrNotExist) {
		return nil, st, ErrInactive
	}
	if err != nil {
		return nil, st, err
	}
	port, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 16)
	if err != nil || port == 0 {
		return nil, st, errors.New("不能读取本机授权状态")
	}
	key, err := grant.LoadIdentity(keyPath)
	if err != nil {
		return nil, st, err
	}
	cfg, err := localTLS(key)
	if err != nil {
		return nil, st, err
	}
	probe, stop := context.WithTimeout(ctx, 4*time.Second)
	defer stop()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	raw, err := (&net.Dialer{}).DialContext(probe, "tcp4", addr)
	if err != nil {
		return nil, st, fmt.Errorf("%w · 后台进程已离线", ErrInactive)
	}
	c := tls.Client(raw, cfg)
	until, _ := probe.Deadline()
	_ = c.SetDeadline(until)
	if err = c.HandshakeContext(probe); err != nil {
		c.Close()
		return nil, st, fmt.Errorf("本机授权进程身份校验失败: %w", err)
	}
	var res reply
	if req.Op == "link" {
		_ = c.SetDeadline(time.Now().Add(40 * time.Second))
	}
	if err = send(c, req); err == nil {
		err = receive(c, &res)
	}
	if err == nil && res.Error != "" {
		err = errors.New(res.Error)
	}
	if err != nil {
		c.Close()
		return nil, st, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, res.State, nil
}

func action(ctx context.Context, path string, r request) (State, error) {
	c, s, err := call(ctx, path, r)
	if c != nil {
		c.Close()
	}
	return s, err
}
func Status(ctx context.Context, path string) (State, error) {
	return action(ctx, path, request{Op: "status"})
}
func Approve(ctx context.Context, path, id string, answer grant.Ticket) error {
	_, err := action(ctx, path, request{Op: "approve", ID: id, Answer: &answer})
	return err
}
func Revoke(ctx context.Context, path, id string) error {
	if _, err := action(ctx, path, request{Op: "revoke", ID: id}); err != nil {
		return err
	}
	until, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-until.Done():
			return errors.New("撤销已发送，后台仍在回收连接")
		case <-tick.C:
		}
		s, err := Status(until, path)
		if err == nil && s.ID != id {
			return nil
		}
		if errors.Is(err, ErrInactive) {
			lease, lockErr := grant.LeaseIdentity(path)
			if errors.Is(lockErr, grant.ErrInUse) {
				continue
			}
			if lockErr != nil {
				return lockErr
			}
			_ = lease.Close()
			return nil
		}
	}
}
func Pipe(ctx context.Context, path, id string) (*tls.Conn, error) {
	c, _, err := call(ctx, path, request{Op: "link", ID: id})
	return c, err
}
