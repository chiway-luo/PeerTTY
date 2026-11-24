package console

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/filelock"
	"peertty/internal/grant"
)

func TestLegacyProxyStopsBeforeConnectingOnLocalHandoffFailures(t *testing.T) {
	for _, tc := range []struct {
		name, stage, want string
	}{
		{"local invocation required", "missing", "请从 PeerTTY"},
		{"absolute identity required", "key", "无效的本地连接参数"},
		{"absolute invitation required", "offer", "无效的本地连接参数"},
		{"absolute response required", "answer", "无效的本地连接参数"},
		{"selected peer required", "peer", "无效的本地连接参数"},
		{"duplicate worker", "worker-busy", ""},
		{"owner menu already closed", "menu-ended", "发起连接的终端已关闭"},
		{"local identity already active", "identity-busy", ""},
		{"private pairing handoff unavailable", "identity-missing", ""},
		{"invitation unreadable", "offer-unreadable", ""},
		{"network config refused before opening sockets", "network-config", "STUN 地址"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			hostPub, hostKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			h := handoff{Key: filepath.Join(dir, "device"), Peer: grant.Fingerprint(hostPub),
				Offer: filepath.Join(dir, "invitation"), Answer: filepath.Join(dir, "receipt"), STUN: "invalid fixture value"}
			if tc.stage != "identity-missing" {
				if _, err := grant.NewIdentity(h.Key); err != nil {
					t.Fatal(err)
				}
			}
			if tc.stage == "offer-unreadable" {
				if err := os.WriteFile(h.Offer, []byte("incomplete local invitation"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				offer, err := grant.NewPairingOffer(hostKey, "test description", "fixture user", time.Now().Add(time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				if err := fixtureCode.Seal(&offer); err != nil {
					t.Fatal(err)
				}
				if tc.stage != "identity-missing" {
					if err := os.WriteFile(h.Offer+".pair", []byte(fixtureCode), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err = offer.WriteNew(h.Offer); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(h.workerPath(), nil, 0600); err != nil {
				t.Fatal(err)
			}
			workerPath, identity, response := h.workerPath(), h.Key, h.Answer
			if tc.stage != "menu-ended" {
				lock, err := filelock.Try(h.Offer)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = lock.Close() })
			}
			switch tc.stage {
			case "worker-busy":
				lock, err := filelock.Try(workerPath)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = lock.Close() })
			case "identity-busy":
				lock, err := grant.LeaseIdentity(identity)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = lock.Close() })
			case "key":
				h.Key = "device"
			case "offer":
				h.Offer = "invitation"
			case "answer":
				h.Answer = "response"
			case "peer":
				h.Peer = ""
			}
			data, err := json.Marshal(h)
			if err != nil {
				t.Fatal(err)
			}
			if tc.stage == "missing" {
				data = nil
			}
			t.Setenv(proxyEnv, string(data))
			err = RunProxy(t.Context(), nil, io.Discard)
			if err == nil || tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("handoff result = %v, want refusal %q", err, tc.want)
			}

			switch tc.stage {
			case "worker-busy":
				if !errors.Is(err, filelock.ErrBusy) {
					t.Fatalf("lost worker contention: %v", err)
				}
			case "identity-busy":
				if !errors.Is(err, grant.ErrInUse) {
					t.Fatalf("lost identity contention: %v", err)
				}
			case "identity-missing":
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("lost missing identity error: %v", err)
				}
			case "offer-unreadable":
				var syntax *json.SyntaxError
				if !errors.As(err, &syntax) {
					t.Fatalf("lost invitation parse error: %v", err)
				}
			}
			if _, err = os.Stat(response); !os.IsNotExist(err) {
				t.Fatalf("failed handoff published a response: %v", err)
			}
			if tc.stage != "worker-busy" {
				lock, err := filelock.Try(workerPath)
				if err != nil {
					t.Fatalf("worker lock was not released: %v", err)
				}
				_ = lock.Close()
			}
			if tc.stage != "identity-busy" && tc.stage != "identity-missing" {
				lock, err := grant.LeaseIdentity(identity)
				if err != nil {
					t.Fatalf("identity lock was not released: %v", err)
				}
				_ = lock.Close()
			}
		})
	}
}
