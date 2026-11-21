// Package session binds one signed authorization to one direct SSH connection.
package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"peertty/internal/bridge"
	"peertty/internal/grant"
	"peertty/internal/localssh"
	"peertty/internal/transport"
)

type Config struct {
	Key        ed25519.PrivateKey
	Peer, STUN string
	// Menu hosts bind to the one reply chosen locally. File-based hosts require a pinned Peer.
	PairOnApproval bool
	SSHUser        string
}

// RunHost publishes an offer and waits for an explicitly approved, matching answer.
func RunHost(parent context.Context, cfg Config, ttl time.Duration, port int, exchange func(context.Context, grant.Ticket) (grant.Ticket, error), connected func(route string, temporarySSH bool)) error {
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
	ctx, cancel := context.WithTimeout(parent, ttl)
	defer cancel()
	expiry, _ := ctx.Deadline()
	peer, err := transport.New(ctx, cfg.STUN)
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
		offer, err = grant.NewPairingOffer(cfg.Key, sdp, cfg.SSHUser, expiry)
	} else {
		offer, err = grant.NewOffer(cfg.Key, cfg.Peer, sdp, expiry)
	}
	if err != nil {
		return err
	}
	answer, err := exchange(ctx, offer)
	if err != nil {
		return err
	}
	if err := answer.VerifyAnswer(offer, time.Now()); err != nil {
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
			return fmt.Errorf("批准后 %s 内未建立直连。被控方（%s），控制方（%s）。可在两端运行网络自检，检查 UDP 和 STUN", checkWindow, transport.CountCandidates(sdp), transport.CountCandidates(answer.Claims.SDP))
		}
		return fmt.Errorf("establish direct path after approval: %w", err)
	}
	conn, err := localssh.Open(peer.Context(), port)
	if err != nil {
		return err
	}
	connected(route, conn.Temporary())
	err = bridge.Run(peer.Context(), wire, conn)
	return errors.Join(err, conn.Release())
}

// RunControl owns the endpoint once the direct connection is established.
func RunControl(parent context.Context, cfg Config, offer grant.Ticket, endpoint bridge.Endpoint, publish func(grant.Ticket) error, connected func(string)) error {
	self := grant.Fingerprint(cfg.Key.Public().(ed25519.PublicKey))
	if err := offer.VerifyOffer(cfg.Peer, self, time.Now()); err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(parent, offer.Deadline())
	defer cancel()
	peer, err := transport.New(ctx, cfg.STUN)
	if err != nil {
		return err
	}
	defer peer.Close()
	sdp, err := peer.Answer(ctx, offer.Claims.SDP)
	if err != nil {
		return err
	}
	answer, err := grant.NewAnswer(cfg.Key, offer, sdp)
	if err != nil {
		return err
	}
	if err := publish(answer); err != nil {
		return err
	}
	wire, route, err := peer.Channel(ctx)
	if err != nil {
		return fmt.Errorf("await host approval and direct path: %w", err)
	}
	connected(route)
	return bridge.Run(peer.Context(), wire, endpoint)
}
