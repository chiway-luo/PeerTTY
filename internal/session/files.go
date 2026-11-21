package session

import (
	"context"
	"crypto/ed25519"
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
}
type HostOptions struct {
	Options
	TTL      time.Duration
	SSHPort  int
	Approval func(context.Context) (string, error)
}

func (o Options) config() Config { return Config{Key: o.Key, Peer: o.Peer, STUN: o.STUN} }

func Host(ctx context.Context, o HostOptions) error {
	return RunHost(ctx, o.config(), o.TTL, o.SSHPort, func(ctx context.Context, offer grant.Ticket) (grant.Ticket, error) {
		if err := offer.WriteNew(o.OfferPath); err != nil {
			return grant.Ticket{}, fmt.Errorf("write offer: %w", err)
		}
		fmt.Fprintf(o.Status, "Share %s with %s. Grant expires %s.\n", o.OfferPath, o.Peer, offer.Deadline().Format(time.RFC3339))
		path, err := o.Approval(ctx)
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
	offer, err := grant.Read(o.OfferPath)
	if err != nil {
		return fmt.Errorf("read offer: %w", err)
	}
	return RunControl(ctx, o.config(), offer, end, func(answer grant.Ticket) error {
		if err := answer.WriteNew(path); err != nil {
			return fmt.Errorf("write answer: %w", err)
		}
		fmt.Fprintf(o.Status, "Return %s to the host for approval.\n", path)
		return nil
	}, func(route string) { fmt.Fprintf(o.Status, "Direct path established (%s).\n", route) })
}
