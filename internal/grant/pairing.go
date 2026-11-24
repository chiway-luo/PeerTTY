package grant

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// PairingCode is shared out of band for one offer. Only a MAC crosses the
// signaling channel. Each proof covers the role and the complete signed ticket,
// including the DTLS fingerprint, expiry and (in an answer) the offer digest.
type PairingCode string

func NewPairingCode() (PairingCode, error) {
	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	return ParsePairingCode(hex.EncodeToString(secret[:]))
}

func ParsePairingCode(input string) (PairingCode, error) {
	raw := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(input), "-", ""))
	if _, err := hex.DecodeString(raw); len(raw) != 32 || err != nil {
		return "", errors.New("请输入被控方提供的完整一次性配对码")
	}
	return PairingCode(strings.Join([]string{raw[:8], raw[8:16], raw[16:24], raw[24:]}, "-")), nil
}

func (code PairingCode) proof(t Ticket) ([]byte, error) {
	canonical, err := ParsePairingCode(string(code))
	if err != nil {
		return nil, err
	}
	if t.Claims.Version != currentVersion || len(t.Signature) != ed25519.SignatureSize || (t.Claims.Kind != "offer" && t.Claims.Kind != "answer") {
		return nil, errors.New("配对凭证无效，请双方升级后重新发起授权")
	}
	mac := hmac.New(sha256.New, []byte(canonical))
	mac.Write([]byte("PeerTTY pairing proof v4\x00" + t.Claims.Kind + "\x00"))
	mac.Write(t.Signature)
	return mac.Sum(nil), nil
}

func ReadPairingCode(path string) (PairingCode, error) {
	data, err := readLimited(path, 128)
	if err != nil {
		return "", err
	}
	return ParsePairingCode(string(data))
}

func (code PairingCode) Seal(t *Ticket) error {
	proof, err := code.proof(*t)
	if err == nil {
		t.PairingProof = proof
	}
	return err
}

// VerifyProof checks the out-of-band credential. Ticket signature and lifetime
// are checked separately so the menu can reject malformed offers before input.
func (code PairingCode) VerifyProof(t Ticket) error {
	proof, err := code.proof(t)
	if err != nil {
		return err
	}
	if !hmac.Equal(t.PairingProof, proof) {
		return errors.New("一次性配对码与本次凭证不匹配")
	}
	return nil
}

func (code PairingCode) VerifyAnswer(offer, answer Ticket, now time.Time) error {
	if err := answer.VerifyAnswer(offer, now); err != nil {
		return err
	}
	return code.VerifyProof(answer)
}
