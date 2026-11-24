package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	MaxTTL         = 24 * time.Hour
	MaxTicketSize  = 128 * 1024
	currentVersion = 4
)

var errTicketLifetime = errors.New("凭证已过期或有效期超出允许范围")

type Claims struct {
	Version     int    `json:"version"`
	OneShot     bool   `json:"one_shot,omitempty"`
	ProfileKey  []byte `json:"profile_key,omitempty"` // Optional additional pin for file-based CLI sessions.
	Kind        string `json:"kind"`
	Session     string `json:"session"`
	ExpiresMS   int64  `json:"expires_ms"`
	Issuer      []byte `json:"issuer"`
	Recipient   string `json:"recipient"`
	OfferDigest string `json:"offer_digest,omitempty"`
	SDP         string `json:"sdp"`
	SSHUser     string `json:"ssh_user,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
	// An offer pins the one-use SSH server; a reply can authorize its client's key.
	SSHHostKey  []byte `json:"ssh_host_key,omitempty"`
	SSHLoginKey []byte `json:"ssh_login_key,omitempty"`
}

type Ticket struct {
	Claims           Claims `json:"claims"`
	Signature        []byte `json:"signature"`
	ProfileSignature []byte `json:"profile_signature,omitempty"`
	PairingProof     []byte `json:"pairing_proof"`
	// Presentation capability outside the signed claims. Older readers ignore it.
	// Only a host advertising this bit can receive a compressed text reply.
	CompactReply bool `json:"compact_reply,omitempty"`
}

func (t Ticket) Deadline() time.Time { return time.UnixMilli(t.Claims.ExpiresMS) }
func (t Ticket) Reusable() bool      { return t.Claims.Version == currentVersion && !t.Claims.OneShot }
func (t Ticket) Pinned() bool        { return len(t.Claims.ProfileKey) != 0 }

// Sender is the additional profile pin when explicitly requested by a CLI
// caller. Issuer always identifies the key that signed this single exchange.
func (t Ticket) Sender() string {
	if t.Pinned() {
		return Fingerprint(t.Claims.ProfileKey)
	}
	return Fingerprint(t.Claims.Issuer)
}

func NewOffer(key ed25519.PrivateKey, recipient, sdp string, deadline time.Time) (Ticket, error) {
	if !ValidFingerprint(recipient) {
		return Ticket{}, errors.New("invalid recipient fingerprint")
	}
	return newOffer(key, true, recipient, sdp, "", nil, deadline)
}

// NewPairingOffer lets the host select the controller by approving its signed reply.
func NewPairingOffer(key ed25519.PrivateKey, sdp, sshUser string, deadline time.Time) (Ticket, error) {
	return newOffer(key, true, "", sdp, sshUser, nil, deadline)
}

func NewLoginOffer(key ed25519.PrivateKey, sdp, sshUser string, host ed25519.PublicKey, deadline time.Time) (Ticket, error) {
	return newOffer(key, false, "", sdp, sshUser, host, deadline)
}

func newOffer(key ed25519.PrivateKey, oneShot bool, recipient, sdp, sshUser string, host ed25519.PublicKey, deadline time.Time) (Ticket, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Ticket{}, err
	}
	claims := Claims{Version: currentVersion, OneShot: oneShot, Kind: "offer", Session: hex.EncodeToString(nonce[:]),
		ExpiresMS: deadline.UnixMilli(), Recipient: recipient, SDP: sdp, SSHUser: sshUser, SSHHostKey: host}
	if recipient != "" {
		return signPinned(key, claims)
	}
	return sign(key, claims)
}

func NewAnswer(key ed25519.PrivateKey, offer Ticket, sdp string) (Ticket, error) {
	return NewLoginAnswer(key, offer, sdp, nil)
}

func NewLoginAnswer(key ed25519.PrivateKey, offer Ticket, sdp string, login ed25519.PublicKey) (Ticket, error) {
	claims := Claims{Version: offer.Claims.Version, OneShot: offer.Claims.OneShot, Kind: "answer", Session: offer.Claims.Session,
		ExpiresMS: offer.Claims.ExpiresMS, Recipient: Fingerprint(offer.Claims.Issuer),
		OfferDigest: offer.digest(), SDP: sdp, SSHLoginKey: login}
	var answer Ticket
	var err error
	if offer.Pinned() {
		answer, err = signPinned(key, claims)
	} else {
		answer, err = sign(key, claims)
	}
	answer.CompactReply = offer.CompactReply
	return answer, err
}

// An optional pre-existing profile key endorses a fresh session signature.
// Copying that profile still does not supply the out-of-band pairing code.
func signPinned(profile ed25519.PrivateKey, claims Claims) (Ticket, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Ticket{}, err
	}
	claims.ProfileKey = profile.Public().(ed25519.PublicKey)
	t, err := sign(key, claims)
	if err == nil {
		t.ProfileSignature = ed25519.Sign(profile, profileMessage(t.Signature))
	}
	return t, err
}

func profileMessage(signature []byte) []byte {
	return append([]byte("PeerTTY optional profile endorsement v4\x00"), signature...)
}

func sign(key ed25519.PrivateKey, claims Claims) (Ticket, error) {
	claims.Issuer = key.Public().(ed25519.PublicKey)
	claims.DeviceName, _ = os.Hostname()
	payload, err := signingBytes(claims)
	if err != nil {
		return Ticket{}, err
	}
	return Ticket{Claims: claims, Signature: ed25519.Sign(key, payload), CompactReply: claims.Kind == "offer"}, nil
}

func signingBytes(c Claims) ([]byte, error) {
	if c.Version != currentVersion {
		return nil, errors.New("不支持的 PeerTTY 凭证版本，请双方升级并重新配对")
	}
	if len(c.ProfileKey) != 0 && (!c.OneShot || len(c.ProfileKey) != ed25519.PublicKeySize) {
		return nil, errors.New("附加设备公钥无效")
	}
	if c.OneShot && (len(c.SSHHostKey) != 0 || len(c.SSHLoginKey) != 0) {
		return nil, errors.New("单连接凭证不应包含会话 SSH 公钥")
	}
	switch c.Kind {
	case "offer":
		if (len(c.ProfileKey) != 0) != (c.Recipient != "") || c.Recipient != "" && !ValidFingerprint(c.Recipient) {
			return nil, errors.New("邀请中的接收方指纹无效")
		}
		if (len(c.SSHHostKey) != 0 && (c.SSHUser == "" || len(c.SSHHostKey) != ed25519.PublicKeySize)) || len(c.SSHLoginKey) != 0 {
			return nil, errors.New("邀请中的 SSH 账号或主机公钥无效")
		}
	case "answer":
		if len(c.SSHHostKey) != 0 || c.SSHUser != "" || (len(c.SSHLoginKey) != 0 && len(c.SSHLoginKey) != ed25519.PublicKeySize) {
			return nil, errors.New("回执中的 SSH 登录公钥无效")
		}
	default:
		return nil, errors.New("未知的凭证类型")
	}
	data, err := json.Marshal(c)
	return append([]byte(fmt.Sprintf("PeerTTY signed session v%d\x00", c.Version)), data...), err
}

func (t Ticket) digest() string {
	digest := sha256.Sum256(t.Signature)
	return hex.EncodeToString(digest[:])
}

func (t Ticket) VerifyOffer(host, operator string, now time.Time) error {
	if t.Claims.OfferDigest != "" {
		return errors.New("邀请中不应包含上级摘要")
	}
	if !ValidFingerprint(host) || !ValidFingerprint(operator) {
		return errors.New("设备指纹格式无效")
	}
	if !t.Pinned() {
		if host == operator {
			return errors.New("不能使用本机签发的邀请控制本机")
		}
		return t.verify("offer", host, "", now)
	}
	return t.verify("offer", host, operator, now)
}

// VerifyOpenOffer checks a non-targeted invitation before the controller
// creates its session key. A device name or an old key is never a self check.
func (t Ticket) VerifyOpenOffer(now time.Time) error {
	if t.Claims.OfferDigest != "" || t.Pinned() {
		return errors.New("需要本次授权的公开邀请")
	}
	return t.verify("offer", Fingerprint(t.Claims.Issuer), "", now)
}

func (t Ticket) VerifyAnswer(offer Ticket, now time.Time) error {
	if offer.Claims.Kind != "offer" || t.Claims.Version != offer.Claims.Version || t.Claims.OneShot != offer.Claims.OneShot || t.Pinned() != offer.Pinned() {
		return errors.New("回执类型或版本与当前邀请不匹配")
	}
	host, operator := Fingerprint(offer.Claims.Issuer), offer.Claims.Recipient
	if !offer.Pinned() {
		operator = Fingerprint(t.Claims.Issuer)
		if offer.Claims.Recipient != "" || operator == host {
			return errors.New("此回执的控制端身份无效")
		}
	}
	if err := t.verify("answer", operator, host, now); err != nil {
		return err
	}
	c := t.Claims
	if len(c.SSHLoginKey) > 0 && len(offer.Claims.SSHHostKey) == 0 {
		return errors.New("当前邀请未启用临时账号公钥登录")
	}
	if c.Session != offer.Claims.Session || c.ExpiresMS != offer.Claims.ExpiresMS || c.OfferDigest != offer.digest() {
		return errors.New("该回执不属于当前邀请")
	}
	return nil
}

func (t Ticket) verify(kind, sender, recipient string, now time.Time) error {
	c := t.Claims
	if c.Kind != kind {
		if kind == "offer" {
			return errors.New("需要的是一份 PeerTTY 邀请，而不是回执")
		}
		return errors.New("需要的是一份 PeerTTY 回执，而不是邀请")
	}
	if len(c.Issuer) != ed25519.PublicKeySize || t.Sender() != sender || c.Recipient != recipient {
		return errors.New("发送方或接收方设备指纹不匹配")
	}
	nonce, err := hex.DecodeString(c.Session)
	if err != nil || len(nonce) != 32 || len(c.SDP) == 0 {
		return errors.New("会话编号无效或缺少连接地址描述")
	}
	payload, err := signingBytes(c)
	if err != nil {
		return err
	}
	if !ed25519.Verify(c.Issuer, payload, t.Signature) {
		return errors.New("凭证签名校验失败，内容可能被篡改或复制不完整")
	}
	if t.Pinned() && !ed25519.Verify(c.ProfileKey, profileMessage(t.Signature), t.ProfileSignature) {
		return errors.New("附加设备签名校验失败")
	}
	life := t.Deadline().Sub(now)
	if life <= 0 || life > MaxTTL+time.Minute {
		return errTicketLifetime
	}
	return nil
}

func Read(path string) (Ticket, error) {
	data, err := readLimited(path, MaxTicketSize)
	if err != nil {
		return Ticket{}, err
	}
	return Parse(data)
}

func Parse(data []byte) (Ticket, error) {
	if len(data) > MaxTicketSize {
		return Ticket{}, errors.New("ticket exceeds size limit")
	}
	var t Ticket
	err := json.Unmarshal(data, &t)
	return t, err
}

func (t Ticket) WriteNew(path string) error {
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	if len(data)+1 > MaxTicketSize {
		return errors.New("connection description exceeds ticket size limit")
	}
	return writeNew(path, append(data, '\n'))
}
