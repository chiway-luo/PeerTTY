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
	MaxTTL          = 24 * time.Hour
	MaxTicketSize   = 128 * 1024
	targetedVersion = 1
	pairingVersion  = 2
	loginVersion    = 3
)

type Claims struct {
	Version     int    `json:"version"`
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
	Claims    Claims `json:"claims"`
	Signature []byte `json:"signature"`
	// Presentation capability outside the signed claims. Older readers ignore it.
	// Only a host advertising this bit can receive a compressed text reply.
	CompactReply bool `json:"compact_reply,omitempty"`
}

func (t Ticket) Deadline() time.Time { return time.UnixMilli(t.Claims.ExpiresMS) }
func (t Ticket) Reusable() bool      { return t.Claims.Version == loginVersion }

func NewOffer(key ed25519.PrivateKey, recipient, sdp string, deadline time.Time) (Ticket, error) {
	if !ValidFingerprint(recipient) {
		return Ticket{}, errors.New("invalid recipient fingerprint")
	}
	return newOffer(key, targetedVersion, recipient, sdp, "", nil, deadline)
}

// NewPairingOffer lets the host select the controller by approving its signed reply.
func NewPairingOffer(key ed25519.PrivateKey, sdp, sshUser string, deadline time.Time) (Ticket, error) {
	return newOffer(key, pairingVersion, "", sdp, sshUser, nil, deadline)
}

func NewLoginOffer(key ed25519.PrivateKey, sdp, sshUser string, host ed25519.PublicKey, deadline time.Time) (Ticket, error) {
	return newOffer(key, loginVersion, "", sdp, sshUser, host, deadline)
}

func newOffer(key ed25519.PrivateKey, version int, recipient, sdp, sshUser string, host ed25519.PublicKey, deadline time.Time) (Ticket, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Ticket{}, err
	}
	return sign(key, Claims{Version: version, Kind: "offer", Session: hex.EncodeToString(nonce[:]),
		ExpiresMS: deadline.UnixMilli(), Recipient: recipient, SDP: sdp, SSHUser: sshUser, SSHHostKey: host})
}

func NewAnswer(key ed25519.PrivateKey, offer Ticket, sdp string) (Ticket, error) {
	return NewLoginAnswer(key, offer, sdp, nil)
}

func NewLoginAnswer(key ed25519.PrivateKey, offer Ticket, sdp string, login ed25519.PublicKey) (Ticket, error) {
	answer, err := sign(key, Claims{Version: offer.Claims.Version, Kind: "answer", Session: offer.Claims.Session,
		ExpiresMS: offer.Claims.ExpiresMS, Recipient: Fingerprint(offer.Claims.Issuer),
		OfferDigest: offer.digest(), SDP: sdp, SSHLoginKey: login})
	answer.CompactReply = offer.CompactReply
	return answer, err
}

func sign(key ed25519.PrivateKey, claims Claims) (Ticket, error) {
	claims.Issuer = key.Public().(ed25519.PublicKey)
	if claims.Version == pairingVersion || claims.Version == loginVersion {
		claims.DeviceName, _ = os.Hostname()
	}
	payload, err := signingBytes(claims)
	if err != nil {
		return Ticket{}, err
	}
	return Ticket{Claims: claims, Signature: ed25519.Sign(key, payload), CompactReply: claims.Kind == "offer"}, nil
}

func signingBytes(c Claims) ([]byte, error) {
	switch c.Version {
	case targetedVersion, pairingVersion:
		if len(c.SSHHostKey) != 0 || len(c.SSHLoginKey) != 0 {
			return nil, errors.New("旧版凭证不应包含会话 SSH 公钥")
		}
	case loginVersion:
		switch c.Kind {
		case "offer":
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
	default:
		return nil, errors.New("不支持的 PeerTTY 凭证版本")
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
	if t.Claims.Version == pairingVersion || t.Claims.Version == loginVersion {
		if host == operator {
			return errors.New("不能使用本机签发的邀请控制本机")
		}
		return t.verify("offer", host, "", now)
	}
	return t.verify("offer", host, operator, now)
}

func (t Ticket) VerifyAnswer(offer Ticket, now time.Time) error {
	if offer.Claims.Kind != "offer" || t.Claims.Version != offer.Claims.Version {
		return errors.New("回执类型或版本与当前邀请不匹配")
	}
	host, operator := Fingerprint(offer.Claims.Issuer), offer.Claims.Recipient
	if offer.Claims.Version == pairingVersion || offer.Claims.Version == loginVersion {
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
	if len(c.Issuer) != ed25519.PublicKeySize || Fingerprint(c.Issuer) != sender || c.Recipient != recipient {
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
	life := t.Deadline().Sub(now)
	if life <= 0 || life > MaxTTL+time.Minute {
		return errors.New("凭证已过期或有效期超出允许范围")
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
