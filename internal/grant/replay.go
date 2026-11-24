package grant

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"peertty/internal/identitystate"
)

var ErrOfferUsed = errors.New("本地已使用过这份邀请，请被控方重新配对")

// Only authenticated invitation identifiers and public expiry times are kept.
// Once an entry is pruned, its expiry is covered by the permanent lower bound.
type replayState struct {
	ExpiredThrough int64            `json:"expired_through_ms"`
	Used           map[string]int64 `json:"used"`
}

// OpenOffer anchors the lifetime before verification and disk I/O. It reserves
// the authenticated offer on this controller before any transport is created.
func (code PairingCode) OpenOffer(parent context.Context, profile string, offer Ticket, host, controller string) (context.Context, context.CancelFunc, error) {
	if err := context.Cause(parent); err != nil {
		return nil, nil, err
	}
	start, err := systemClock()
	if err != nil {
		return nil, nil, err
	}
	if err = code.consumeOffer(profile, offer, host, controller, start.wall, time.Now); err != nil {
		return nil, nil, err
	}
	return withLifetime(parent, offer.Deadline(), start, systemClock)
}

func (code PairingCode) consumeOffer(profile string, offer Ticket, host, controller string, now time.Time, clock func() time.Time) error {
	if err := offer.VerifyOffer(host, controller, now); err != nil {
		// Remember a genuinely expired invitation only after its signature
		// and pairing proof have both authenticated it.
		if !errors.Is(err, errTicketLifetime) || offer.Deadline().After(now) {
			return err
		}
	}
	if err := code.VerifyProof(offer); err != nil {
		return err
	}
	if !filepath.IsAbs(profile) {
		return errors.New("缺少记录已用邀请的本地配置路径")
	}
	var decision error
	path := identitystate.RuntimePath(profile, "used-offers.json")
	err := identitystate.UpdateDurable(path, 4<<20, func(data []byte) ([]byte, error) {
		var state replayState
		if data == nil {
			state.Used = make(map[string]int64)
		} else {
			// A missing floor must not reset a previously pruned history.
			state.ExpiredThrough = -1
			if err := json.Unmarshal(data, &state); err != nil || state.Used == nil || state.ExpiredThrough < 0 {
				return nil, errors.New("本地邀请使用记录无效")
			}
		}
		// Time may have changed while waiting for the cross-process lock.
		observed := max(now.UnixMilli(), clock().UnixMilli())
		changed := false
		for id, expiry := range state.Used {
			if raw, err := hex.DecodeString(id); err != nil || len(raw) != 32 || expiry <= 0 {
				return nil, errors.New("本地邀请使用记录无效")
			}
			if expiry <= observed {
				state.ExpiredThrough = max(state.ExpiredThrough, expiry)
				delete(state.Used, id)
				changed = true
			}
		}
		expiry, id := offer.Claims.ExpiresMS, offer.Claims.Session
		switch {
		case expiry <= state.ExpiredThrough:
			decision = errTicketLifetime
		case expiry <= observed:
			state.ExpiredThrough = expiry
			decision, changed = errTicketLifetime, true
		case state.Used[id] != 0:
			decision = ErrOfferUsed
		default:
			state.Used[id] = expiry
			changed = true
		}
		if !changed {
			return nil, nil
		}
		return json.Marshal(state)
	})
	return errors.Join(err, decision)
}
