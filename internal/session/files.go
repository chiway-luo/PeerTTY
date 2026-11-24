package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"time"

	"peertty/internal/bridge"
	"peertty/internal/grant"
)

// Options belongs to the CLI file-exchange adapter.
type Options struct {
	Key                   ed25519.PrivateKey
	Peer, STUN, OfferPath string
	Status                io.Writer
	PairingCode           grant.PairingCode
}
type HostOptions struct {
	Options
	TTL      time.Duration
	SSHPort  int
	Approval func(context.Context, grant.PairingCode) (string, error)
}

func (o Options) config() Config {
	return Config{Key: o.Key, Peer: o.Peer, STUN: o.STUN, PairOnApproval: o.Peer == "", PairingCode: o.PairingCode}
}

func Host(ctx context.Context, o HostOptions) error {
	return nativeSessionIO().fileHost(ctx, o)
}

func (deps sessionIO) fileHost(ctx context.Context, o HostOptions) error {
	return deps.host(ctx, o.config(), o.TTL, o.SSHPort, func(ctx context.Context, offer grant.Ticket, code grant.PairingCode) (grant.Ticket, error) {
		if err := offer.WriteNew(o.OfferPath); err != nil {
			return grant.Ticket{}, fmt.Errorf("write offer: %w", err)
		}
		fmt.Fprintf(o.Status, "Share %s. Grant expires %s.\nPairing code (deliver separately): %s\n", o.OfferPath, offer.Deadline().Format(time.RFC3339), code)
		path, err := o.Approval(ctx, code)
		if err != nil {
			return grant.Ticket{}, err
		}
		ticket, err := grant.Read(path)
		if err != nil {
			return grant.Ticket{}, fmt.Errorf("read answer: %w", err)
		}
		return ticket, nil
	}, func(route string, temporary bool) {
		if temporary {
			fmt.Fprintln(o.Status, "Started temporary OpenSSH on 127.0.0.1:22 for this grant.")
		}
		fmt.Fprintf(o.Status, "Direct path established (%s). Serving one SSH session.\n", route)
	})
}
func Connect(ctx context.Context, o Options, path string, end bridge.Endpoint) error {
	return nativeSessionIO().fileConnect(ctx, o, path, end)
}

func (deps sessionIO) fileConnect(ctx context.Context, o Options, path string, end bridge.Endpoint) error {
	offer, err := grant.Read(o.OfferPath)
	if err != nil {
		return fmt.Errorf("read offer: %w", err)
	}
	if o.Peer != "" && !offer.Pinned() {
		return errors.New("当前命令固定了设备公钥，需要定向邀请")
	}
	return deps.control(ctx, o.config(), offer, end, func(answer grant.Ticket) error {
		if err := answer.WriteNew(path); err != nil {
			return fmt.Errorf("write answer: %w", err)
		}
		fmt.Fprintf(o.Status, "Return %s to the host for approval.\n", path)
		return nil
	}, func(route string) { fmt.Fprintf(o.Status, "Direct path established (%s).\n", route) })
}
