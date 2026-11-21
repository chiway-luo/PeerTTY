package active

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/grant"
)

func TestLocalFramesStaySeparate(t *testing.T) {
	var stream bytes.Buffer
	first := request{Op: "status", ID: "one"}
	second := request{Op: "revoke", ID: "two"}
	for _, req := range []request{first, second} {
		if err := send(&stream, req); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []request{first, second} {
		var got request
		if err := receive(&stream, &got); err != nil || got != want {
			t.Fatalf("frame: %+v, %v", got, err)
		}
	}
	if err := receive(&stream, &request{}); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end: %v", err)
	}
	if err := send(&stream, strings.Repeat("x", frameLimit)); err == nil || stream.Len() != 0 {
		t.Fatal("oversized frame reached stream")
	}
}

func TestLocalFrameBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    uint32
		payload string
	}{
		{"empty", 0, ""}, {"over limit", frameLimit + 1, ""}, {"truncated", 8, "{}"}, {"invalid JSON", 1, "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := binary.BigEndian.AppendUint32(nil, tc.size)
			if err := receive(bytes.NewReader(append(data, tc.payload...)), &reply{}); err == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
}

func TestRejectedBootstrapLeavesNoActiveGrant(t *testing.T) {
	key := filepath.Join(t.TempDir(), "device.key")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	for _, opt := range []Options{
		{Role: "other", Key: key},
		{Role: "host", Key: key, Port: 22, TTL: 0},
		{Role: "host", Key: key, Port: 65536, TTL: time.Minute},
		{Role: "control", Key: key},
	} {
		var input, ready bytes.Buffer
		if err := send(&input, opt); err != nil {
			t.Fatal(err)
		}
		if err := Serve(t.Context(), &input, &ready); err == nil || ready.Len() != 0 {
			t.Fatalf("rejected bootstrap %q reported readiness", opt.Role)
		}
		if _, err := Status(t.Context(), key); !errors.Is(err, ErrInactive) {
			t.Fatalf("stale state: %v", err)
		}
	}
	for _, port := range []string{"0", "65536", "unreadable"} {
		if err := os.WriteFile(key+".active", []byte(port), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Status(t.Context(), key); err == nil || errors.Is(err, ErrInactive) {
			t.Fatalf("corrupt rendezvous %q: %v", port, err)
		}
	}
}

func TestConcurrentTerminalLimitAndSlotReuse(t *testing.T) {
	var w worker
	const attempts = 64
	start := make(chan struct{})
	result := make(chan bool, attempts)
	for range attempts {
		go func() {
			<-start
			result <- w.enter()
		}()
	}
	close(start)
	admitted := 0
	for range attempts {
		if <-result {
			admitted++
		}
	}
	if admitted != 32 || w.snapshot().Terminals != admitted {
		t.Fatalf("admitted %d, reported %d", admitted, w.snapshot().Terminals)
	}
	w.leave()
	if !w.enter() {
		t.Fatal("released slot was not reusable")
	}
	w.stopping = true
	for range admitted {
		w.leave()
	}
	w.links.Wait()
	if w.enter() || w.snapshot().Terminals != 0 {
		t.Fatal("stopping worker accepted a new terminal")
	}
}

func TestWorkerAcceptsOneApprovalForTheCurrentGrant(t *testing.T) {
	_, hostKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, clientKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := grant.NewPairingOffer(hostKey, "local offer", "operator", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	answer, err := grant.NewAnswer(clientKey, offer, "local answer")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := localTLS(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	w := worker{offer: offer, state: State{ID: "current", Role: "host", Phase: "waiting"}, approval: make(chan grant.Ticket, 1)}
	revoked := false
	callWorker := func(req request) reply {
		t.Helper()
		left, right := net.Pipe()
		defer left.Close()
		if err := left.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			w.handle(t.Context(), tls.Server(right, cfg), func() { revoked = true })
		}()
		client := tls.Client(left, cfg)
		if err := send(client, req); err != nil {
			t.Fatal(err)
		}
		var res reply
		if err := receive(client, &res); err != nil {
			t.Fatal(err)
		}
		left.Close()
		<-done
		return res
	}
	for _, invalid := range []request{
		{Op: "approve", ID: "expired", Answer: &answer},
		{Op: "approve", ID: "current"},
		{Op: "revoke", ID: "expired"},
		{Op: "link", ID: "current"},
		{Op: "unknown", ID: "current"},
	} {
		if res := callWorker(invalid); res.Error == "" || w.snapshot().Phase != "waiting" || revoked {
			t.Fatalf("invalid %q changed the grant", invalid.Op)
		}
	}
	approval := request{Op: "approve", ID: "current", Answer: &answer}
	if res := callWorker(approval); res.Error != "" || res.State.Phase != "connecting" {
		t.Fatalf("approval: %+v", res)
	}
	select {
	case got := <-w.approval:
		if !bytes.Equal(got.Signature, answer.Signature) {
			t.Fatal("wrong signed answer delivered")
		}
	default:
		t.Fatal("no approval delivered")
	}
	if res := callWorker(approval); res.Error == "" || len(w.approval) != 0 {
		t.Fatal("duplicate approval accepted")
	}
	if res := callWorker(request{Op: "revoke", ID: "current"}); res.Error != "" || !revoked {
		t.Fatal("current grant not revoked", res.Error)
	}
}
