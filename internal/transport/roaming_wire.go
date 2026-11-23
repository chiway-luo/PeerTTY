package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"github.com/pion/transport/v5/replaydetector"
)

// Each offer and answer signs a fresh X25519 public key inside its SDP. Only
// the two owners of those keys can validate paths or carry the original ICE
// datagrams. Opposite directions use distinct keys and monotonically increasing
// nonces. There is no recoverable key on disk when the grant ends.
const roamAttribute = "x-peertty-roam-v1"
const roamMagic = "\xf9PT\x01"
const (
	pathChallenge byte = 1
	pathResponse  byte = 2
	pathData      byte = 3
)

type roamCipher struct {
	send, receive cipher.AEAD
	serial        atomic.Uint64
	mu            sync.Mutex
	replay        replaydetector.ReplayDetector
}

func newRoamCipher(local *ecdh.PrivateKey, encoded string, receiptSignature []byte, offerer bool) (*roamCipher, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	remote, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil || remote.Equal(local.PublicKey()) {
		return nil, errors.New("invalid roaming public key")
	}
	secret, err := local.ECDH(remote)
	if err != nil {
		return nil, err
	}
	keys, err := hkdf.Key(sha256.New, secret, receiptSignature, "PeerTTY direct path v1", 64)
	if err != nil {
		return nil, err
	}
	makeAEAD := func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	a, err := makeAEAD(keys[:32])
	if err != nil {
		return nil, err
	}
	b, err := makeAEAD(keys[32:])
	if err != nil {
		return nil, err
	}
	if !offerer {
		a, b = b, a
	}
	return &roamCipher{send: a, receive: b, replay: replaydetector.New(256, math.MaxUint64)}, nil
}

func (c *roamCipher) seal(kind byte, body []byte) []byte {
	const header = 12
	buf := make([]byte, header+1+len(body), header+1+len(body)+c.send.Overhead())
	copy(buf, roamMagic)
	binary.BigEndian.PutUint64(buf[4:header], c.serial.Add(1))
	buf[header] = kind
	copy(buf[header+1:], body)
	return c.send.Seal(buf[:header], buf[:header], buf[header:], nil)
}

func (c *roamCipher) open(wire []byte) (byte, []byte, bool) {
	const header = 12
	if len(wire) < header+1+c.receive.Overhead() || string(wire[:4]) != roamMagic {
		return 0, nil, false
	}
	body, err := c.receive.Open(wire[header:header], wire[:header], wire[header:], nil)
	if err != nil {
		return 0, nil, false
	}
	seq := binary.BigEndian.Uint64(wire[4:header])
	c.mu.Lock()
	defer c.mu.Unlock()
	accept, fresh := c.replay.Check(seq)
	if !fresh || seq == 0 {
		return 0, nil, false
	}
	accept()
	return body[0], body[1:], true
}
