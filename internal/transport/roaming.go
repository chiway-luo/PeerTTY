package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v4"
)

const pathLifetime = 10 * time.Second

type routeChallenge struct {
	token        [16]byte
	issued, sent time.Time
}

// One instance belongs to one PeerConnection for the whole signed grant. ICE
// still verifies consent, DTLS still pins the peer certificate, and SCTP still
// owns every terminal stream. Only the UDP path beneath them can change.
type roaming struct {
	ctx           context.Context
	done          chan struct{}
	closeOnce     sync.Once
	key           *ecdh.PrivateKey
	keys          atomic.Pointer[roamCipher]
	mu            sync.Mutex
	remoteKey     string
	offerer       bool
	targets       []netip.AddrPort
	recent        []netip.AddrPort // bounded, previously authenticated peer endpoints
	logical       wirePath         // ICE's selected candidate socket and remote address
	physical      wirePath         // independently validated path on the current network
	lastProof     time.Time
	confirmed     map[wirePath]time.Time
	challenges    map[wirePath]routeChallenge
	started       time.Time
	initialChecks map[wirePath]time.Time
	nominated     bool
}

func newRoaming(ctx context.Context) (*roaming, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &roaming{ctx: ctx, done: make(chan struct{}), key: key, confirmed: make(map[wirePath]time.Time),
		challenges: make(map[wirePath]routeChallenge)}, nil
}

// The worker cancels admission and all SSH streams before sending REVOKE on
// the grant's reliable control stream. Keep its already validated path alive
// for that final exchange, until Peer.Close releases the actual transport.
func (r *roaming) close() { r.closeOnce.Do(func() { close(r.done) }) }

func (r *roaming) advertise(sdp string) string {
	return sdp + "a=" + roamAttribute + ":" + base64.RawStdEncoding.EncodeToString(r.key.PublicKey().Bytes()) + "\r\n"
}

func (r *roaming) setRemote(key string, offerer bool, targets []netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remoteKey, r.offerer, r.targets = key, offerer, targets
}

func (r *roaming) enable(receiptSignature []byte, connected func() bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.remoteKey
	if key == "" { // A previous release uses ordinary ICE throughout.
		return nil
	}
	if len(receiptSignature) != ed25519.SignatureSize || r.keys.Load() != nil {
		return errors.New("expected a single signed receipt for direct path recovery")
	}
	keys, err := newRoamCipher(r.key, key, receiptSignature, r.offerer)
	if err != nil {
		return err
	}
	r.started = time.Now()
	r.initialChecks = make(map[wirePath]time.Time)
	r.keys.Store(keys)
	go r.search(connected)
	return nil
}

func (r *roaming) write(pair wirePath, data []byte) (bool, error) {
	keys := r.keys.Load()
	if keys == nil || len(data) == 0 {
		return false, nil
	}
	r.mu.Lock()
	// Pion only emits DTLS on its nominated pair. Before the first handshake
	// a connectivity check also gives us a pair to carry across a moved link.
	if data[0] >= 20 && data[0] <= 63 {
		r.logical = pair
		r.nominated = true
		r.initialChecks = nil
	} else if !r.nominated && iceCheck(data) {
		if r.logical.socket == nil {
			r.logical = pair
		}
		// A person can deliver the receipt long after the first ICE checklist.
		// Keep it eligible until expiry without sending at ICE's initial rate.
		now := time.Now()
		if r.physical.socket == nil && now.Sub(r.started) > 8*time.Second {
			if now.Sub(r.initialChecks[pair]) < 3*time.Second {
				r.mu.Unlock()
				return true, nil
			}
			r.initialChecks[pair] = now
		}
	}
	path := r.physical
	use := path.socket != nil && r.logical == pair
	r.mu.Unlock()
	if !use {
		return false, nil
	}
	// UDP transmission errors during an interface change are transient. Keep
	// ICE/SCTP alive to retransmit over the next validated path.
	err := path.send(keys, pathData, data)
	if routeUnavailable(err) || errors.Is(err, net.ErrClosed) {
		return true, nil
	}
	return true, err
}

func iceCheck(data []byte) bool {
	m := stun.Message{Raw: data}
	return stun.IsMessage(data) && m.Decode() == nil && m.Type == stun.BindingRequest &&
		m.Contains(stun.AttrUsername) && m.Contains(stun.AttrMessageIntegrity)
}

func (r *roaming) receive(src wirePath, data []byte) {
	select {
	case <-r.done:
		return
	default:
	}
	keys := r.keys.Load()
	if keys == nil {
		return
	}
	frame, ok := keys.decrypt(data)
	if !ok || (frame.kind != pathData && r.ctx.Err() != nil) {
		return
	}
	body := frame.body
	now := time.Now()
	r.mu.Lock()
	switch frame.kind {
	case pathChallenge:
		valid := len(body) == 16 && keys.accept(frame.seq)
		r.mu.Unlock()
		if valid {
			_ = src.send(keys, pathResponse, body)
			r.challenge(src, now)
		}
	case pathResponse:
		pending, found := r.challenges[src]
		if found && len(body) == 16 && [16]byte(body) == pending.token && now.Sub(pending.issued) < pathLifetime && keys.accept(frame.seq) {
			delete(r.challenges, src)
			if len(r.confirmed) < 64 || !r.confirmed[src].IsZero() {
				r.confirmed[src] = now
				if !slices.Contains(r.recent, src.addr) {
					if len(r.recent) == 16 {
						r.recent = r.recent[1:]
					}
					r.recent = append(r.recent, src.addr)
				}
				if r.logical.socket != nil && (r.physical.socket == nil || r.physical == src || now.Sub(r.lastProof) > 4*time.Second) {
					r.physical, r.lastProof = src, now
				}
			}
		}
		r.mu.Unlock()
	case pathData:
		_, verified := r.confirmed[src]
		pair := r.logical
		deliver := verified && pair.socket != nil && len(body) != 0 && keys.accept(frame.seq)
		r.mu.Unlock()
		if deliver {
			pair.socket.deliver(body, net.UDPAddrFromAddrPort(pair.addr))
		}
	default:
		r.mu.Unlock()
	}
}

func (r *roaming) challenge(path wirePath, now time.Time) {
	if r.ctx.Err() != nil {
		return
	}
	r.mu.Lock()
	ch, pending := r.challenges[path]
	if pending && now.Sub(ch.sent) < 1500*time.Millisecond {
		r.mu.Unlock()
		return
	}
	// A recent successful challenge needs no immediate reciprocal challenge.
	if t := r.confirmed[path]; !t.IsZero() && now.Sub(t) < 2*time.Second {
		r.mu.Unlock()
		return
	}
	if !pending && len(r.challenges) >= 128 {
		r.mu.Unlock()
		return
	}
	if !pending || now.Sub(ch.issued) >= pathLifetime {
		ch.issued = now
		rand.Read(ch.token[:])
	}
	ch.sent = now
	r.challenges[path] = ch
	r.mu.Unlock()
	_ = path.send(r.keys.Load(), pathChallenge, ch.token[:])
}

func (r *roaming) search(connected func() bool) {
	r.searchWith(connected, func(network string) (*roamSocket, error) {
		c, err := net.ListenUDP(network, &net.UDPAddr{})
		if err != nil {
			return nil, err
		}
		return r.socket(c, false), nil
	})
}

func (r *roaming) searchWith(connected func() bool, openSpare func(string) (*roamSocket, error)) {
	var spare [2]*roamSocket
	defer func() {
		for _, s := range spare {
			if s != nil {
				s.Close()
			}
		}
	}()
	start := time.Now()
	wasUp := false
	nextTarget := 0
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-r.ctx.Done():
			<-r.done
			return
		case <-r.done:
			return
		case now := <-timer.C:
			up := connected()
			wasUp = wasUp || up
			r.mu.Lock()
			for p, ch := range r.challenges {
				if now.Sub(ch.issued) >= pathLifetime {
					delete(r.challenges, p)
				}
			}
			for p, proof := range r.confirmed {
				if p != r.physical && now.Sub(proof) > time.Minute {
					delete(r.confirmed, p)
				}
			}
			logical, path, lastProof := r.logical, r.physical, r.lastProof
			if path.socket != nil {
				// ICE can keep receiving one-way traffic after a second handover.
				// Verify our actual egress tuple even when Pion still reports up.
				r.mu.Unlock()
				r.challenge(path, now)
				r.mu.Lock()
			}
			healthy := up && (path.socket == nil || now.Sub(lastProof) < 6*time.Second)
			if logical.socket == nil || healthy || (!wasUp && now.Sub(start) < 8*time.Second) {
				r.mu.Unlock()
				continue
			}
			targets := slices.Clone(r.recent)
			for _, ep := range []netip.AddrPort{path.addr, logical.addr} {
				if ep.IsValid() && !slices.Contains(targets, ep) {
					targets = append(targets, ep)
				}
			}
			// Cycle through the whole signed list on multihomed machines without
			// sending a burst to every interface on each tick.
			for range min(16, len(r.targets)) {
				ep := r.targets[nextTarget]
				nextTarget = (nextTarget + 1) % len(r.targets)
				if !slices.Contains(targets, ep) {
					targets = append(targets, ep)
				}
			}
			r.mu.Unlock()
			for _, dst := range targets {
				if dst.Addr().IsLoopback() && !logical.addr.Addr().IsLoopback() {
					continue
				}
				if dst.Addr().Is4() == logical.addr.Addr().Is4() {
					r.challenge(wirePath{logical.socket, dst}, now)
				}
				family, network := 0, "udp4"
				if !dst.Addr().Is4() {
					family, network = 1, "udp6"
				}
				if spare[family] == nil {
					s, err := openSpare(network)
					if err != nil {
						continue
					}
					spare[family] = s
				}
				r.challenge(wirePath{spare[family], dst}, now)
			}
		}
	}
}
