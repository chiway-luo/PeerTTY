package grant

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func TestSigningSchemaRejectsUnsupportedFieldsBeforeSerialization(t *testing.T) {
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	short := key[:len(key)-1]
	for _, tc := range []struct {
		name   string
		claims Claims
		want   string
	}{
		{"unsupported version", Claims{Version: 999, Kind: "offer"}, "凭证版本"},
		{"unsupported kind", Claims{Version: currentVersion, Kind: "status"}, "凭证类型"},
		{"legacy offer with new host field", Claims{Version: currentVersion, OneShot: true, Kind: "offer", SSHHostKey: key}, "单连接凭证"},
		{"legacy answer with new login field", Claims{Version: currentVersion, OneShot: true, Kind: "answer", SSHLoginKey: key}, "单连接凭证"},
		{"offer has key but no user", Claims{Version: currentVersion, Kind: "offer", SSHHostKey: key}, "SSH 账号"},
		{"offer has invalid key length", Claims{Version: currentVersion, Kind: "offer", SSHUser: "robot", SSHHostKey: short}, "SSH 账号"},
		{"offer has answer-only field", Claims{Version: currentVersion, Kind: "offer", SSHLoginKey: key}, "SSH 账号"},
		{"answer has offer host key", Claims{Version: currentVersion, Kind: "answer", SSHHostKey: key}, "SSH 登录公钥"},
		{"answer has offer account", Claims{Version: currentVersion, Kind: "answer", SSHUser: "robot"}, "SSH 登录公钥"},
		{"answer has invalid key length", Claims{Version: currentVersion, Kind: "answer", SSHLoginKey: short}, "SSH 登录公钥"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := signingBytes(tc.claims)
			if err == nil || !strings.Contains(err.Error(), tc.want) || len(got) != 0 {
				t.Fatalf("wrong rejection: returned %d bytes, %v", len(got), err)
			}
		})
	}
}

func TestTicketValidationRejectsIncompatibleLocalInputs(t *testing.T) {
	host, hostKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	operator, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	until := now.Add(time.Minute)
	if ticket, err := NewOffer(hostKey, "unrecognized device", "fixture", until); err == nil || len(ticket.Signature) != 0 {
		t.Fatalf("invalid recipient returned a signed invite: %v", err)
	}
	offer, err := NewLoginOffer(hostKey, "fixture", "robot", nil, until)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"invalid", Fingerprint(operator)}, {Fingerprint(host), "invalid"}} {
		if err := offer.VerifyOffer(pair[0], pair[1], now); err == nil || !strings.Contains(err.Error(), "指纹格式") {
			t.Fatalf("invalid local device metadata did not report invalid fingerprints: %v", err)
		}
	}
	legacy, err := NewPairingOffer(hostKey, "fixture", "robot", until)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.VerifyAnswer(offer, now); err == nil || !strings.Contains(err.Error(), "类型或版本") {
		t.Fatalf("different formats did not report a version mismatch: %v", err)
	}
}

func TestOfferVerificationRejectsIncompleteLocalTicketRecords(t *testing.T) {
	host, hostKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	operator, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	valid, err := NewLoginOffer(hostKey, "fixture candidate description", "robot", nil, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		edit       func(*Ticket)
	}{
		{"accidentally chose a reply", "需要的是一份 PeerTTY 邀请", func(t *Ticket) { t.Claims.Kind = "answer" }},
		{"missing issuer", "设备指纹不匹配", func(t *Ticket) { t.Claims.Issuer = nil }},
		{"unexpected reply digest", "不应包含上级摘要", func(t *Ticket) { t.Claims.OfferDigest = "receipt-only" }},
		{"nonhex session identifier", "会话编号无效", func(t *Ticket) { t.Claims.Session = "fixture" }},
		{"truncated session identifier", "会话编号无效", func(t *Ticket) { t.Claims.Session = "1234" }},
		{"empty connection description", "缺少连接地址描述", func(t *Ticket) { t.Claims.SDP = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			incomplete := valid
			tc.edit(&incomplete)
			if err := incomplete.VerifyOffer(Fingerprint(host), Fingerprint(operator), now); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
	if err := valid.VerifyOffer(Fingerprint(host), Fingerprint(operator), now); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
}
