package active

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pion/datachannel"
	"peertty/internal/bridge"
	"peertty/internal/grant"
	"peertty/internal/localssh"
	"peertty/internal/transport"
)

type Options struct {
	Role, Key, STUN, User, Identity, SSHConfig string
	TTL                                        time.Duration
	Port                                       int
	Offer                                      grant.Ticket
	Scoped                                     bool
}

type worker struct {
	Options
	key      ed25519.PrivateKey
	dir      string
	mu       sync.Mutex
	state    State
	offer    grant.Ticket
	approval chan grant.Ticket
	peer     *transport.Peer
	login    *localssh.Login
	openSSH  sync.Mutex
	links    sync.WaitGroup
	stopping bool
}

// Serve is the detached process entry point. A closed UI never approves a reply.
func Serve(parent context.Context, in io.Reader, started io.Writer) (result error) {
	var opts Options
	if err := receive(in, &opts); err != nil {
		return err
	}
	if !filepath.IsAbs(opts.Key) {
		return errors.New("需要本机设备身份的完整路径")
	}
	key, err := grant.LoadIdentity(opts.Key)
	if err != nil {
		return err
	}
	now := time.Now()
	deadline := now.Add(opts.TTL)
	switch opts.Role {
	case "host":
		if opts.TTL <= 0 || opts.TTL > grant.MaxTTL || opts.Port < 1 || opts.Port > 65535 {
			return errors.New("授权时长或 SSH 端口无效")
		}
	case "control":
		if !opts.Offer.Reusable() {
			return errors.New("旧邀请需使用前台 SSH 连接")
		}
		if err = opts.Offer.VerifyOffer(grant.Fingerprint(opts.Offer.Claims.Issuer), grant.Fingerprint(key.Public().(ed25519.PublicKey)), now); err != nil {
			return err
		}
		deadline = opts.Offer.Deadline()
	default:
		return errors.New("未知授权角色")
	}
	lease, err := grant.LeaseIdentity(opts.Key)
	if err != nil {
		return err
	}
	defer lease.Close()
	dir, err := os.MkdirTemp("", "peertty-grant-*")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(dir)) }()
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	w := &worker{Options: opts, key: key, dir: dir, approval: make(chan grant.Ticket, 1),
		state: State{ID: filepath.Base(dir), Role: opts.Role, Deadline: deadline, Phase: "gathering", User: opts.User, Identity: opts.Identity, SSHConfig: opts.SSHConfig}}
	tlsCfg, err := localTLS(key)
	if err != nil {
		return err
	}
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	listener := tls.NewListener(raw, tlsCfg)
	defer listener.Close()
	stopListener := context.AfterFunc(ctx, func() { listener.Close() })
	defer stopListener()
	// Publish atomically while holding the same identity lease as the foreground CLI.
	discovery := opts.Key + ".active"
	tmp, err := os.CreateTemp(filepath.Dir(discovery), ".peertty-port-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = fmt.Fprintln(tmp, raw.Addr().(*net.TCPAddr).Port)
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), discovery); err != nil {
		return err
	}
	defer os.Remove(discovery)
	if err = send(started, reply{State: w.state}); err != nil {
		return err
	}
	if started == os.Stdout {
		_ = os.Stdout.Close()
	}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go w.handle(ctx, c.(*tls.Conn), cancel)
		}
	}()
	err = w.run(ctx)
	if err != nil && ctx.Err() == nil {
		keep := 3 * time.Second
		if w.snapshot().Route != "" {
			keep = time.Until(deadline)
		}
		w.update(func(s *State) { s.Phase = "offline"; s.Note = err.Error() })
		// Preserve a readable failure while attached menus report it. A
		// failed negotiation releases the role instead of trapping a new grant.
		timer := time.NewTimer(keep)
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
	}
	w.mu.Lock()
	w.stopping = true
	w.mu.Unlock()
	cancel()
	listener.Close()
	<-serveDone
	w.links.Wait()
	if w.login != nil {
		return w.login.Close()
	}
	return nil
}

func (w *worker) update(f func(*State)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f(&w.state)
}
func (w *worker) snapshot() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.state
	if s.Phase == "ready" && w.peer != nil && !w.peer.Connected() {
		s.Phase = "disconnected"
	}
	return s
}

func (w *worker) run(ctx context.Context) error {
	p, err := transport.NewGrant(ctx, w.STUN)
	if err != nil {
		return err
	}
	defer p.Close()
	var ticket grant.Ticket
	var loginKey ed25519.PublicKey
	var answerSDP string
	if w.Role == "host" {
		sdp, err := p.Offer(ctx)
		if err != nil {
			return err
		}
		var name string
		if account, err := user.Current(); err == nil {
			name = account.Username
		}
		var hostKey ed25519.PublicKey
		if w.Port == 22 {
			w.login, err = localssh.PrepareLogin(ctx)
			if err == nil {
				name, hostKey = w.login.User, w.login.HostKey
			} else {
				w.update(func(s *State) { s.Note = err.Error() })
			}
		}
		ticket, err = grant.NewLoginOffer(w.key, sdp, name, hostKey, w.state.Deadline)
		if err != nil {
			return err
		}
		path := filepath.Join(w.dir, "session.offer")
		if err = ticket.WriteNew(path); err != nil {
			return err
		}
		w.mu.Lock()
		w.offer = ticket
		w.state.Phase = "waiting"
		w.state.User = name
		w.state.Exchange = path
		w.mu.Unlock()
		var answer grant.Ticket
		select {
		case <-ctx.Done():
			return ctx.Err()
		case answer = <-w.approval:
		}
		loginKey = answer.Claims.SSHLoginKey
		answerSDP = answer.Claims.SDP
		if len(loginKey) > 0 {
			if w.login == nil {
				return errors.New("本机没有授权此账号")
			}
			if err = w.login.Authorize(loginKey); err != nil {
				return err
			}
		}
		p.OnLink(func(stream datachannel.ReadWriteCloserDeadliner) { w.serveSSH(p.Context(), stream, len(loginKey) > 0) })
		if err = p.Accept(answer.Claims.SDP); err != nil {
			return err
		}
	} else {
		offer := w.Offer
		sdp, err := p.Answer(ctx, offer.Claims.SDP)
		if err != nil {
			return err
		}
		alias := "peertty-" + strings.TrimPrefix(grant.Fingerprint(offer.Claims.Issuer), "sha256:")
		identity, known := w.Identity, ""
		if w.Scoped {
			if len(offer.Claims.SSHHostKey) == 0 || w.User != offer.Claims.SSHUser {
				return errors.New("本次授权不包含该登录账号")
			}
			identity = filepath.Join(w.dir, "login.key")
			known = filepath.Join(w.dir, "known_hosts")
			loginKey, err = localssh.NewLoginKey(identity)
			if err != nil {
				return err
			}
			if err = localssh.PinLoginHost(known, alias, offer.Claims.SSHHostKey); err != nil {
				return err
			}
		}
		answer, err := grant.NewLoginAnswer(w.key, offer, sdp, loginKey)
		if err != nil {
			return err
		}
		path := filepath.Join(w.dir, "session.answer")
		if err = answer.WriteNew(path); err != nil {
			return err
		}
		w.update(func(s *State) {
			s.Phase = "waiting"
			s.Exchange = path
			s.Alias = alias
			s.Identity = identity
			s.KnownHosts = known
			s.Device = offer.Claims.DeviceName
		})
	}
	negotiating := ctx
	if w.Role == "host" {
		var stop context.CancelFunc
		negotiating, stop = context.WithTimeout(ctx, time.Minute)
		defer stop()
	}
	control, route, err := p.Channel(negotiating)
	if err != nil {
		if w.Role == "host" && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("批准后 60 秒内未建立直连。被控方（%s），控制方（%s）", transport.CountCandidates(ticket.Claims.SDP), transport.CountCandidates(answerSDP))
		}
		return fmt.Errorf("双方未建立直连 · %w", err)
	}
	defer control.Close()
	w.mu.Lock()
	w.peer = p
	w.state.Phase = "ready"
	w.state.Route = route
	w.mu.Unlock()
	// This first stream belongs to the grant. Individual SSH windows use
	// separate streams and can close without ending the approved connection.
	remoteClosed := make(chan error, 1)
	go func() {
		buf := make([]byte, 16*1024)
		n, text, err := control.ReadDataChannel(buf)
		if err == nil {
			switch {
			case text && string(buf[:n]) == "REVOKE":
				_ = control.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = control.WriteDataChannel([]byte("CLOSED"), true)
			case text && string(buf[:n]) == "CLOSED" && ctx.Err() != nil:
			default:
				err = errors.New("对端返回了未知的授权状态")
			}
		}
		if err != nil {
			err = fmt.Errorf("授权状态通道已关闭 · %w", err)
		}
		remoteClosed <- err
	}()
	select {
	case <-ctx.Done():
	case <-p.Context().Done():
		if ctx.Err() == nil {
			select {
			case err := <-remoteClosed:
				return err
			case <-time.After(250 * time.Millisecond):
				return context.Cause(p.Context())
			}
		}
	case err := <-remoteClosed:
		return err
	}
	_ = control.SetWriteDeadline(time.Now().Add(time.Second))
	if _, e := control.WriteDataChannel([]byte("REVOKE"), true); e == nil {
		select {
		case <-remoteClosed:
		case <-time.After(3 * time.Second):
		}
	}
	return ctx.Err()
}

func (w *worker) enter() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopping || w.state.Terminals >= 32 {
		return false
	}
	w.links.Add(1)
	w.state.Terminals++
	return true
}
func (w *worker) leave() {
	w.update(func(s *State) { s.Terminals-- })
	w.links.Done()
}

func (w *worker) serveSSH(ctx context.Context, stream datachannel.ReadWriteCloserDeadliner, scoped bool) {
	defer stream.Close()
	if ctx.Err() != nil || !w.enter() {
		return
	}
	defer w.leave()
	w.openSSH.Lock()
	var c *localssh.Conn
	var err error
	if scoped {
		c, err = w.login.OpenAuthorized(ctx)
	} else {
		c, err = localssh.Open(ctx, w.Port)
	}
	w.openSSH.Unlock()
	if err != nil {
		w.update(func(s *State) { s.Note = err.Error() })
		return
	}
	defer c.Release()
	if err := bridge.Run(ctx, stream, c); err != nil && ctx.Err() == nil {
		w.update(func(s *State) { s.Note = "SSH 终端已断开 · " + err.Error() })
	}
}

func (w *worker) handle(ctx context.Context, c *tls.Conn, cancel context.CancelFunc) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var req request
	if err := receive(c, &req); err != nil {
		return
	}
	w.mu.Lock()
	s := w.state
	p := w.peer
	var err error
	if req.Op != "status" && (req.ID != s.ID || w.stopping || ctx.Err() != nil) {
		err = errors.New("本次授权已结束")
	} else {
		switch req.Op {
		case "status":
		case "revoke":
			w.stopping = true
		case "approve":
			if s.Role != "host" || s.Phase != "waiting" || req.Answer == nil {
				err = errors.New("本次授权无法再次批准")
			} else if err = req.Answer.VerifyAnswer(w.offer, time.Now()); err == nil {
				w.state.Phase = "connecting"
				w.state.Device = req.Answer.Claims.DeviceName
				w.approval <- *req.Answer
			}
		case "link":
			if s.Role != "control" || s.Phase != "ready" || p == nil || !p.Connected() {
				err = errors.New("尚未建立已授权的直连")
			}
		default:
			err = errors.New("未知的本机操作")
		}
	}
	w.mu.Unlock()
	if err != nil {
		_ = send(c, reply{Error: err.Error()})
		return
	}
	if req.Op != "link" {
		_ = send(c, reply{State: w.snapshot()})
		if req.Op == "revoke" {
			cancel()
		}
		return
	}
	if !w.enter() {
		_ = send(c, reply{Error: "本次授权已结束或终端数已达上限"})
		return
	}
	defer w.leave()
	_ = c.SetDeadline(time.Now().Add(40 * time.Second))
	open, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	stream, err := p.OpenLink(open)
	if err != nil {
		_ = send(c, reply{Error: err.Error()})
		return
	}
	defer stream.Close()
	if err = send(c, reply{State: s}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	_ = bridge.Run(p.Context(), stream, c)
}
