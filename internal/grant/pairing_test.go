package grant

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClonedProfilesRequireOneOfferCodeAndExactSignedEndpoints(t *testing.T) {
	pub, imageKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := Fingerprint(pub)
	now := time.Now()
	code, err := NewPairingCode()
	if err != nil {
		t.Fatal(err)
	}
	nextCode, err := NewPairingCode()
	if err != nil || code == nextCode {
		t.Fatal("expected independent grant codes", err)
	}
	offer, err := NewOffer(imageKey, id, "host description", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = code.Seal(&offer); err != nil {
		t.Fatal(err)
	}
	if err = offer.VerifyOffer(id, id, now); err != nil {
		t.Fatal(err)
	}
	if err = code.VerifyProof(offer); err != nil {
		t.Fatal(err)
	}
	answer, err := NewAnswer(imageKey, offer, "controller description")
	if err != nil {
		t.Fatal(err)
	}
	if err = code.Seal(&answer); err != nil {
		t.Fatal(err)
	}
	if err = answer.VerifyAnswer(offer, now); err != nil {
		t.Fatal(err)
	}
	if err = code.VerifyProof(answer); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(offer.Claims.Issuer, pub) || bytes.Equal(answer.Claims.Issuer, pub) || bytes.Equal(answer.Claims.Issuer, offer.Claims.Issuer) {
		t.Fatal("a session reused the cloned profile or its peer's signing key")
	}
	for _, ticket := range []Ticket{offer, answer} {
		encoded, err := json.Marshal(ticket)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(code)) || bytes.Contains(encoded, []byte(strings.ReplaceAll(string(code), "-", ""))) {
			t.Fatal("pairing code appeared in the exchange")
		}
		if nextCode.VerifyProof(ticket) == nil {
			t.Fatal("another grant's code verified this exchange")
		}
	}
	other, err := NewAnswer(imageKey, offer, "another controller description")
	if err != nil {
		t.Fatal(err)
	}
	other.PairingProof = answer.PairingProof
	if other.VerifyAnswer(offer, now) != nil || code.VerifyProof(other) == nil {
		t.Fatal("a copy of the profile and public proof admitted a different signed endpoint")
	}
	copyOfAnswer := answer
	copyOfAnswer.Claims.SDP = "changed endpoint"
	if copyOfAnswer.VerifyAnswer(offer, now) == nil {
		t.Fatal("changed DTLS description passed signature verification")
	}
	next, err := NewOffer(imageKey, id, offer.Claims.SDP, offer.Deadline())
	if err != nil {
		t.Fatal(err)
	}
	if answer.VerifyAnswer(next, now) == nil || bytes.Equal(next.Claims.Issuer, offer.Claims.Issuer) {
		t.Fatal("new grant accepted a previous receipt or reused its signing key")
	}
	badPin := answer
	badPin.ProfileSignature = nil
	if code.VerifyAnswer(offer, badPin, now) == nil {
		t.Fatal("missing optional pin endorsement was accepted")
	}
	reflected := answer
	reflected.PairingProof = offer.PairingProof
	if code.VerifyAnswer(offer, reflected, now) == nil {
		t.Fatal("offer proof authorized an answer")
	}
	legacy := Ticket{Claims: Claims{Version: 3, Kind: "offer", Session: offer.Claims.Session, Issuer: pub, ExpiresMS: offer.Claims.ExpiresMS, SDP: "old host"}}
	oldBody, err := json.Marshal(legacy.Claims)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Signature = ed25519.Sign(imageKey, append([]byte("PeerTTY signed session v3\x00"), oldBody...))
	if legacy.VerifyOpenOffer(now) == nil || code.VerifyProof(legacy) == nil {
		t.Fatal("old version admitted")
	}
}
