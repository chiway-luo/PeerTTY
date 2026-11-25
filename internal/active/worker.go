package active

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
	RequireScoped                              bool
	PairingCode                                grant.PairingCode
}

// workerPeer is the direct transport owned by the grant worker.
type workerPeer interface {
	Context() context.Context
	Connected() bool
	CanRoam() bool
	Migrated() bool
	Close() error
	Offer(context.Context) (string, error)
	Answer(context.Context, string) (string, error)
	Accept(string) error
	OnLink(func(datachannel.ReadWriteCloserDeadliner))
	OpenLink(context.Context) (datachannel.ReadWriteCloserDeadliner, error)
	BindGrant([]byte) error
	Channel(context.Context) (datachannel.ReadWriteCloserDeadliner, string, error)
}

type worker struct {
	Options
	key      ed25519.PrivateKey
	dir      string
	mu       sync.Mutex
	state    State
	offer    grant.Ticket
	approval chan grant.Ticket
	peer     workerPeer
	linkCtx  context.Context
	endLinks context.CancelFunc
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
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	now := time.Now()
	deadline := now.Add(opts.TTL)
	switch opts.Role {
	case "host":
		if opts.TTL <= 0 || opts.TTL > grant.MaxTTL || opts.Port < 1 || opts.Port > 65535 || (opts.RequireScoped && opts.Port != 22) {
			return errors.New("授权时长或 SSH 端口无效")
		}
		opts.PairingCode, err = grant.NewPairingCode()
		if err != nil {
			return err
		}
	case "control":
		if !opts.Offer.Reusable() {
			return errors.New("此邀请不支持当前后台授权，请双方升级后重新配对")
		}
	default:
		return errors.New("未知授权角色")
	}
	lease, err := grant.LeaseIdentity(opts.Key)
	if err != nil {
		return err
	}
	defer lease.Close()
	var ctx context.Context
	var cancel context.CancelFunc
	if opts.Role == "host" {
		ctx, cancel, err = grant.WithLifetime(parent, deadline)
	} else {
		ctx, cancel, err = opts.PairingCode.OpenOffer(parent, opts.Key, opts.Offer,
			grant.Fingerprint(opts.Offer.Claims.Issuer), grant.Fingerprint(key.Public().(ed25519.PublicKey)))
	}
	if err != nil {
		return err
	}
	defer cancel()
	deadline, _ = ctx.Deadline()
	dir, err := os.MkdirTemp("", "peertty-grant-*")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(dir)) }()
	w := &worker{Options: opts, key: key, dir: dir, approval: make(chan grant.Ticket, 1),
		state: State{ID: filepath.Base(dir), Role: opts.Role, Deadline: deadline, Phase: "gathering", User: opts.User, Identity: opts.Identity, SSHConfig: opts.SSHConfig, RequireScoped: opts.RequireScoped}}
	if opts.Role == "host" {
		w.state.PairingCode = opts.PairingCode
	}
	closeEndpoint, err := serveControl(ctx, opts.Key, func(c *tls.Conn) { w.handle(ctx, c, cancel) })
	if err != nil {
		return err
	}
	defer closeEndpoint()
	if err = send(started, reply{State: w.snapshot().withRemaining(ctx)}); err != nil {
		return err
	}
	if started == os.Stdout {
		_ = os.Stdout.Close()
	}
	clearLastError(opts.Key)
	logWorkerEvent(w.state.ID, fmt.Sprintf("start role=%s deadline=%s", opts.Role, deadline.Format(time.RFC3339)))
	err = w.run(ctx)
	if err != nil && ctx.Err() == nil {
		logWorkerEvent(w.state.ID, "offline: "+err.Error())
		writeLastError(opts.Key, err.Error())
		w.update(func(s *State) { s.Phase = "offline"; s.Note = err.Error() })
		// Allow menus to read the reason, then release the identity for pairing.
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
	} else {
		logWorkerEvent(w.state.ID, "ended")
	}
	w.mu.Lock()
	w.stopping = true
	w.mu.Unlock()
	cancel()
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
	} else if s.Phase == "ready" && w.peer != nil && w.peer.Migrated() {
		s.Route = "udp · 换网直连"
	}
	return s
}

// SSH streams share a lifetime within the grant. After a sustained outage,
// close those streams but keep the signed peer available for a new window.
func (w *worker) resetLinks(parent context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.endLinks != nil {
		w.endLinks()
	}
	w.linkCtx, w.endLinks = context.WithCancel(parent)
}

func (w *worker) run(ctx context.Context) error {
	p, err := transport.NewGrant(ctx, w.STUN)
	if err != nil {
		return err
	}
	return w.runWithPeer(ctx, p)
}

func (w *worker) runWithPeer(ctx context.Context, p workerPeer) error {
	return w.runWithLoginPrep(ctx, p, localssh.PrepareLogin)
}

func (w *worker) runWithLoginPrep(ctx context.Context, p workerPeer, prepare func(context.Context) (*localssh.Login, error)) error {
	defer p.Close()
	var err error
	w.resetLinks(p.Context())
	var ticket grant.Ticket
	var loginKey ed25519.PublicKey
	var answerSDP string
	var receiptSignature []byte
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
			w.login, err = prepare(ctx)
			if err == nil {
				name, hostKey = w.login.User, w.login.HostKey
			} else if w.RequireScoped {
				return fmt.Errorf("本次授权账号的临时 SSH 复查失败: %w", err)
			} else {
				w.update(func(s *State) { s.Note = err.Error() })
			}
		}
		ticket, err = grant.NewLoginOffer(w.key, sdp, name, hostKey, w.state.Deadline)
		if err != nil {
			return err
		}
		if err = w.PairingCode.Seal(&ticket); err != nil {
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
		if err := grant.CheckLifetime(ctx); err != nil {
			return err
		}
		receiptSignature = answer.Signature
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
		p.OnLink(func(stream datachannel.ReadWriteCloserDeadliner) {
			w.mu.Lock()
			link := w.linkCtx
			w.mu.Unlock()
			w.serveSSH(link, stream, len(loginKey) > 0)
		})
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
		if err = w.PairingCode.Seal(&answer); err != nil {
			return err
		}
		if err = grant.CheckLifetime(ctx); err != nil {
			return err
		}
		receiptSignature = answer.Signature
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
	if err := p.BindGrant(receiptSignature); err != nil {
		return err
	}
	negotiating := ctx
	if w.Role == "host" {
		var stop context.CancelFunc
		negotiating, stop = context.WithTimeout(ctx, time.Minute)
		defer stop()
	}
	control, route, err := p.Channel(negotiating)
	var waitingNote string
	if w.Role == "host" && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		reason := fmt.Sprintf("批准后 60 秒内未建立直连。被控方（%s），控制方（%s）", transport.CountCandidates(ticket.Claims.SDP), transport.CountCandidates(answerSDP))
		if !p.CanRoam() {
			return errors.New(reason)
		}
		waitingNote = reason + "。授权期内继续等待可达路径。"
		w.update(func(s *State) { s.Note = waitingNote })
		control, route, err = p.Channel(ctx)
	}
	if err != nil {
		return fmt.Errorf("双方未建立直连 · %w", err)
	}
	defer control.Close()
	if err := grant.CheckLifetime(ctx); err != nil {
		return err
	}
	w.mu.Lock()
	if w.state.Note == waitingNote {
		w.state.Note = ""
	}
	w.peer = p
	w.state.Phase = "ready"
	w.state.Route = route
	w.mu.Unlock()
	logWorkerEvent(w.state.ID, "connected route="+route)
	// This first stream belongs to the grant. Individual SSH windows use
	// separate streams and can close without ending the approved connection.
	remoteClosed := make(chan error, 1)
	go func() {
		remoteClosed <- readGrantClosure(ctx, control, func() {
			logWorkerEvent(w.state.ID, "remote peer revoked grant")
		})
	}()
	err = waitForGrantEndWithNotice(ctx, p.Context(), p.Connected, remoteClosed, func() {
		logWorkerEvent(w.state.ID, "route lost for 15s; closing stalled SSH streams")
		w.resetLinks(p.Context())
	}, func(prolonged bool) {
		w.update(func(s *State) {
			if prolonged {
				s.Note = prolongedOutageText
			} else if s.Note == prolongedOutageText {
				s.Note = ""
			}
		})
	})
	if ctx.Err() == nil {
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

type grantControlStream interface {
	ReadDataChannel([]byte) (int, bool, error)
	WriteDataChannel([]byte, bool) (int, error)
	SetWriteDeadline(time.Time) error
}

// readGrantClosure handles the one final message on the grant control stream.
func readGrantClosure(ctx context.Context, control grantControlStream, onRevoke func()) error {
	buf := make([]byte, 16*1024)
	n, text, err := control.ReadDataChannel(buf)
	if err == nil {
		switch {
		case text && string(buf[:n]) == "REVOKE":
			onRevoke()
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
	return err
}

const (
	routeRecoveryWindow   = 15 * time.Second
	prolongedOutageWindow = 60 * time.Second
	prolongedOutageText   = "网络已持续中断超过 1 分钟。授权期内会继续尝试直连。若双方已知地址均不可达，可运行 /revoke 并重新配对。"
)

// Give live terminals a short recovery window, independently of the grant's
// signed deadline and the time a person needs to approve the receipt.
func waitForGrantEnd(ctx, peer context.Context, connected func() bool, remoteClosed <-chan error, closeStalled func()) error {
	return waitForGrantEndWithNotice(ctx, peer, connected, remoteClosed, closeStalled, nil)
}

func waitForGrantEndWithNotice(ctx, peer context.Context, connected func() bool, remoteClosed <-chan error, closeStalled func(), onProlonged func(bool)) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	return waitForGrantEndEvents(ctx, peer, connected, remoteClosed, tick.C, closeStalled, onProlonged)
}

func waitForGrantEndEvents(ctx, peer context.Context, connected func() bool, remoteClosed <-chan error, ticks <-chan time.Time, closeStalled func(), onProlonged func(bool)) error {
	var lostAt time.Time
	var stalled, warned bool
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-peer.Done():
			select {
			case err := <-remoteClosed:
				return err
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
				return context.Cause(peer)
			}
		case err := <-remoteClosed:
			return err
		case now := <-ticks:
			if connected() {
				if warned && onProlonged != nil {
					onProlonged(false)
				}
				lostAt = time.Time{}
				stalled = false
				warned = false
			} else if lostAt.IsZero() {
				lostAt = now
			} else {
				elapsed := now.Sub(lostAt)
				if !stalled && elapsed >= routeRecoveryWindow {
					closeStalled()
					stalled = true
				}
				if !warned && elapsed >= prolongedOutageWindow {
					warned = true
					if onProlonged != nil {
						onProlonged(true)
					}
				}
			}
		}
	}
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
	if grant.CheckLifetime(ctx) != nil || !w.enter() {
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

// acceptRequest owns the grant state transition and captures the link inputs
// under the same lock. I/O remains outside the lock in handle.
func (w *worker) acceptRequest(ctx context.Context, req request, now time.Time) (State, workerPeer, context.Context, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.state
	p := w.peer
	link := w.linkCtx
	var err error
	if req.Op != "status" && (req.ID != s.ID || w.stopping || grant.CheckLifetime(ctx) != nil) {
		err = errors.New("本次授权已结束")
	} else if s.OneShot && req.Op != "status" && req.Op != "revoke" {
		err = ErrOneShot
	} else {
		switch req.Op {
		case "status":
		case "revoke":
			w.stopping = true
		case "approve":
			if s.Role != "host" || s.Phase != "waiting" || req.Answer == nil {
				err = errors.New("本次授权无法再次批准")
			} else if err = s.CheckAnswer(w.offer, *req.Answer, now); err == nil {
				w.state.Phase = "connecting"
				w.state.Device = req.Answer.Claims.DeviceName
				w.state.PairingCode = ""
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
	return s, p, link, err
}

func (w *worker) handle(ctx context.Context, c *tls.Conn, cancel context.CancelFunc) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var req request
	if err := receive(c, &req); err != nil {
		return
	}
	s, p, link, err := w.acceptRequest(ctx, req, time.Now())
	if err != nil {
		_ = send(c, reply{Error: err.Error()})
		return
	}
	if req.Op != "link" {
		_ = send(c, reply{State: w.snapshot().withRemaining(ctx)})
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
	open, stop := context.WithTimeout(link, 30*time.Second)
	defer stop()
	stream, err := p.OpenLink(open)
	if err != nil {
		_ = send(c, reply{Error: err.Error()})
		return
	}
	defer stream.Close()
	if err = grant.CheckLifetime(link); err != nil {
		_ = send(c, reply{Error: err.Error()})
		return
	}
	if err = send(c, reply{State: s}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	_ = bridge.Run(link, stream, c)
}
