// Package session binds one signed authorization to one direct SSH connection.
package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/pion/datachannel"

	"peertty/internal/bridge"
	"peertty/internal/grant"
	"peertty/internal/localssh"
	"peertty/internal/transport"
)

type Config struct {
	Key        ed25519.PrivateKey
	Peer, STUN string
	Profile    string // Absolute controller profile used to reject spent invitations.
	// Menu hosts bind to the one reply chosen locally. File-based hosts require a pinned Peer.
	PairOnApproval bool
	SSHUser        string
	PairingCode    grant.PairingCode // Received independently by the controller.
}

// sessionPeer is the transport surface used by the one-shot CLI session.
type sessionPeer interface {
	Context() context.Context
	Close() error
	Offer(context.Context) (string, error)
	Answer(context.Context, string) (string, error)
	Accept(string) error
	Channel(context.Context) (datachannel.ReadWriteCloserDeadliner, string, error)
}

type localEndpoint interface {
	bridge.Endpoint
	Temporary() bool
	Release() error
}

type sessionIO struct {
	peer func(context.Context, string) (sessionPeer, error)
	open func(context.Context, int) (localEndpoint, error)
	run  func(context.Context, bridge.Channel, bridge.Endpoint) error
}

func nativeSessionIO() sessionIO {
	return sessionIO{
		peer: func(ctx context.Context, spec string) (sessionPeer, error) { return transport.New(ctx, spec) },
		open: func(ctx context.Context, port int) (localEndpoint, error) { return localssh.Open(ctx, port) },
		run:  bridge.Run,
	}
}

// RunHost publishes an offer and waits for an explicitly approved, matching answer.
func RunHost(parent context.Context, cfg Config, ttl time.Duration, port int, exchange func(context.Context, grant.Ticket, grant.PairingCode) (grant.Ticket, error), connected func(route string, temporarySSH bool)) error {
	return nativeSessionIO().host(parent, cfg, ttl, port, exchange, connected)
}

func (deps sessionIO) host(parent context.Context, cfg Config, ttl time.Duration, port int, exchange func(context.Context, grant.Ticket, grant.PairingCode) (grant.Ticket, error), connected func(string, bool)) error {
	if ttl <= 0 || ttl > grant.MaxTTL {
		return fmt.Errorf("TTL must be positive and at most %s", grant.MaxTTL)
	}
	if port < 1 || port > 65535 {
		return errors.New("invalid local SSH port")
	}
	if cfg.PairOnApproval && cfg.Peer != "" {
		return errors.New("cannot combine pairing on approval with a pinned controller")
	}
	if !cfg.PairOnApproval && !grant.ValidFingerprint(cfg.Peer) {
		return errors.New("expected the operator's full sha256 fingerprint")
	}
	ctx, cancel, err := grant.WithLifetime(parent, time.Now().Add(ttl))
	if err != nil {
		return err
	}
	defer cancel()
	expiry, _ := ctx.Deadline()
	peer, err := deps.peer(ctx, cfg.STUN)
	if err != nil {
		return err
	}
	defer peer.Close()
	sdp, err := peer.Offer(ctx)
	if err != nil {
		return err
	}
	var offer grant.Ticket
	if cfg.PairOnApproval {
		_, key, keyErr := ed25519.GenerateKey(nil)
		if keyErr != nil {
			return keyErr
		}
		offer, err = grant.NewPairingOffer(key, sdp, cfg.SSHUser, expiry)
	} else {
		if len(cfg.Key) != ed25519.PrivateKeySize {
			return errors.New("缺少指定的设备密钥")
		}
		offer, err = grant.NewOffer(cfg.Key, cfg.Peer, sdp, expiry)
	}
	if err != nil {
		return err
	}
	code, err := grant.NewPairingCode()
	if err != nil {
		return err
	}
	if err = code.Seal(&offer); err != nil {
		return err
	}
	answer, err := exchange(ctx, offer, code)
	if err != nil {
		return err
	}
	if err := code.VerifyAnswer(offer, answer, time.Now()); err != nil {
		return err
	}
	if err := grant.CheckLifetime(ctx); err != nil {
		return err
	}
	if err := peer.Accept(answer.Claims.SDP); err != nil {
		return err
	}
	const checkWindow = 60 * time.Second
	connectCtx, stop := context.WithTimeout(ctx, checkWindow)
	wire, route, err := peer.Channel(connectCtx)
	stop()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("批准后 %s 内未建立直连。被控方（%s），控制方（%s）。请检查 UDP 打洞条件，或确认至少一端的 TCP 监听地址可从对端到达", checkWindow, transport.CountCandidates(sdp), transport.CountCandidates(answer.Claims.SDP))
		}
		return fmt.Errorf("establish direct path after approval: %w", err)
	}
	if err := grant.CheckLifetime(ctx); err != nil {
		return err
	}
	conn, err := deps.open(peer.Context(), port)
	if err != nil {
		return err
	}
	connected(route, conn.Temporary())
	err = deps.run(peer.Context(), wire, conn)
	return errors.Join(err, conn.Release())
}

// RunControl owns the endpoint once the direct connection is established.
func RunControl(parent context.Context, cfg Config, offer grant.Ticket, endpoint bridge.Endpoint, publish func(grant.Ticket) error, connected func(string)) error {
	return nativeSessionIO().control(parent, cfg, offer, endpoint, publish, connected)
}

func (deps sessionIO) control(parent context.Context, cfg Config, offer grant.Ticket, endpoint bridge.Endpoint, publish func(grant.Ticket) error, connected func(string)) error {
	key := cfg.Key
	if offer.Pinned() {
		if len(key) != ed25519.PrivateKeySize || cfg.Peer == "" {
			return errors.New("定向邀请需要双方指定设备指纹")
		}
	} else {
		var err error
		_, key, err = ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
	}
	peerID := cfg.Peer
	if peerID == "" {
		peerID = offer.Sender()
	}
	if offer.Reusable() {
		return errors.New("请在菜单打开多终端授权邀请")
	}
	ctx, cancel, err := cfg.PairingCode.OpenOffer(parent, cfg.Profile, offer, peerID, grant.Fingerprint(key.Public().(ed25519.PublicKey)))
	if err != nil {
		return err
	}
	defer cancel()
	peer, err := deps.peer(ctx, cfg.STUN)
	if err != nil {
		return err
	}
	defer peer.Close()
	sdp, err := peer.Answer(ctx, offer.Claims.SDP)
	if err != nil {
		return err
	}
	answer, err := grant.NewAnswer(key, offer, sdp)
	if err != nil {
		return err
	}
	if err = cfg.PairingCode.Seal(&answer); err != nil {
		return err
	}
	if err := grant.CheckLifetime(ctx); err != nil {
		return err
	}
	if err := publish(answer); err != nil {
		return err
	}
	wire, route, err := peer.Channel(ctx)
	if err != nil {
		return fmt.Errorf("await host approval and direct path: %w", err)
	}
	if err := grant.CheckLifetime(ctx); err != nil {
		return err
	}
	connected(route)
	return deps.run(peer.Context(), wire, endpoint)
}
