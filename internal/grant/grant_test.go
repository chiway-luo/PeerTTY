package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIdentityLeaseAndRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.key")
	if _, err := NewIdentity(path); err != nil {
		t.Fatal(err)
	}
	first, err := LeaseIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := LoadIdentity(path); err != nil {
		t.Fatal("fingerprint lookup while locked:", err)
	}
	second, err := LeaseIdentity(path)
	if second != nil {
		second.Close()
	}
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("second role accepted: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err = LeaseIdentity(path)
	if err != nil {
		t.Fatal("release:", err)
	}
	second.Close()
}

func TestTicketBinding(t *testing.T) {
	hostPub, host, _ := ed25519.GenerateKey(rand.Reader)
	operatorPub, operator, _ := ed25519.GenerateKey(rand.Reader)
	hostID, operatorID := Fingerprint(hostPub), Fingerprint(operatorPub)
	now := time.Now()
	offer, err := NewOffer(host, operatorID, "offer sdp", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := offer.VerifyOffer(hostID, operatorID, now); err != nil {
		t.Fatal(err)
	}
	answer, err := NewAnswer(operator, offer, "answer sdp")
	if err != nil {
		t.Fatal(err)
	}
	if err := answer.VerifyAnswer(offer, now); err != nil {
		t.Fatal(err)
	}
	other, err := NewOffer(host, operatorID, "offer sdp", offer.Deadline())
	if err != nil {
		t.Fatal(err)
	}
	if err := answer.VerifyAnswer(other, now); err == nil {
		t.Fatal("accepted an answer from another session")
	}
	for _, test := range []struct {
		name  string
		check func() error
	}{
		{"wrong host", func() error { return offer.VerifyOffer(operatorID, operatorID, now) }},
		{"wrong operator", func() error { return offer.VerifyOffer(hostID, hostID, now) }},
		{"expired", func() error { return offer.VerifyOffer(hostID, operatorID, offer.Deadline()) }},
		{"role swapped", func() error { return offer.VerifyAnswer(offer, now) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.check() == nil {
				t.Fatal("accepted invalid grant")
			}
		})
	}
	answer.Claims.SDP += "changed"
	if err := answer.VerifyAnswer(offer, now); err == nil {
		t.Fatal("accepted modified connection information")
	}
}

func TestPrivateKeyAndGrantFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.key")
	id, err := NewIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewIdentity(path); !os.IsExist(err) {
		t.Fatalf("overwriting key: %v", err)
	}
	key, err := LoadIdentity(path)
	if err != nil || Fingerprint(key.Public().(ed25519.PublicKey)) != id {
		t.Fatal("identity mismatch", err)
	}
	offer, err := NewOffer(key, id, "sdp", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "session.offer")
	if err := offer.WriteNew(file); err != nil {
		t.Fatal(err)
	}
	if err := offer.WriteNew(file); !os.IsExist(err) {
		t.Fatalf("overwriting offer: %v", err)
	}
	loaded, err := Read(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.VerifyOffer(id, id, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestPairingReplyBindsBothKeysAndExactInvitation(t *testing.T) {
	hostPub, host, _ := ed25519.GenerateKey(rand.Reader)
	operatorPub, operator, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, other, _ := ed25519.GenerateKey(rand.Reader)
	hostID, operatorID := Fingerprint(hostPub), Fingerprint(operatorPub)
	now := time.Now()
	offer, err := NewPairingOffer(host, "offer", "local-user", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err = offer.VerifyOffer(hostID, operatorID, now); err != nil {
		t.Fatal(err)
	}
	answer, err := NewAnswer(operator, offer, "answer")
	if err != nil {
		t.Fatal(err)
	}
	if err = answer.VerifyAnswer(offer, now); err != nil {
		t.Fatal(err)
	}
	otherOffer, _ := NewPairingOffer(host, "offer", "local-user", offer.Deadline())
	targeted, _ := NewOffer(host, Fingerprint(otherPub), "targeted", offer.Deadline())
	legacyReply, _ := NewAnswer(other, targeted, "answer")
	selfReply, _ := NewAnswer(host, offer, "answer")
	modified := answer
	modified.Claims.Issuer = otherPub
	wrongHost, _ := sign(operator, Claims{Version: pairingVersion, Kind: "answer", Session: offer.Claims.Session,
		ExpiresMS: offer.Claims.ExpiresMS, Recipient: Fingerprint(otherPub), OfferDigest: offer.digest(), SDP: "answer"})
	badUser := offer
	badUser.Claims.SSHUser = "different"
	for name, err := range map[string]error{
		"replay": answer.VerifyAnswer(otherOffer, now), "expired": answer.VerifyAnswer(offer, offer.Deadline()),
		"self reply": selfReply.VerifyAnswer(offer, now), "substituted key": modified.VerifyAnswer(offer, now),
		"wrong recipient": wrongHost.VerifyAnswer(offer, now), "modified account": badUser.VerifyOffer(hostID, operatorID, now),
		"other recipient v1": targeted.VerifyOffer(hostID, operatorID, now),
		"v1 reply to v2":     legacyReply.VerifyAnswer(offer, now), "v2 reply to v1": answer.VerifyAnswer(targeted, now),
		"self offer": offer.VerifyOffer(hostID, hostID, now),
	} {
		if err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestLoginKeysBoundToApprovedAccountAndDeadline(t *testing.T) {
	hpub, h, _ := ed25519.GenerateKey(rand.Reader)
	cpub, c, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _, _ := ed25519.GenerateKey(rand.Reader)
	loginKey, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	offer, err := NewLoginOffer(h, "offer", "alice", hostKey, now.Add(24*time.Hour))
	if err != nil || offer.VerifyOffer(Fingerprint(hpub), Fingerprint(cpub), now) != nil {
		t.Fatal("24-hour offer rejected", err)
	}
	answer, err := NewLoginAnswer(c, offer, "reply", loginKey)
	if err != nil || answer.VerifyAnswer(offer, now) != nil {
		t.Fatal("login reply rejected", err)
	}
	forged := offer
	forged.Claims.SSHHostKey = loginKey
	if forged.VerifyOffer(Fingerprint(hpub), Fingerprint(cpub), now) == nil {
		t.Fatal("accepted substituted SSH host key")
	}
	forged = answer
	forged.Claims.SSHLoginKey = hostKey
	if forged.VerifyAnswer(offer, now) == nil {
		t.Fatal("accepted substituted controller key")
	}
	other, _ := NewLoginOffer(h, "offer", "alice", hostKey, now.Add(time.Hour))
	if answer.VerifyAnswer(other, now) == nil {
		t.Fatal("accepted reply for another grant")
	}
	if answer.VerifyAnswer(offer, offer.Deadline()) == nil {
		t.Fatal("accepted an expired grant")
	}
	legacy, _ := NewPairingOffer(h, "offer", "alice", now.Add(time.Hour))
	if _, err = NewLoginAnswer(c, legacy, "reply", loginKey); err == nil {
		t.Fatal("accepted login key on legacy reply")
	}
	native, _ := NewLoginOffer(h, "offer", "alice", nil, now.Add(time.Hour))
	invalid, _ := NewLoginAnswer(c, native, "reply", loginKey)
	if invalid.VerifyAnswer(native, now) == nil {
		t.Fatal("native-only invite allowed a session key")
	}
}
