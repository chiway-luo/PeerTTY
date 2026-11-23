package console

import (
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
)

func TestCompressedTicketRoundTripLegacyAndZipBombDefense(t *testing.T) {
	// Realistic repetitive SDP compresses dramatically with zlib.
	ticket := grant.Ticket{
		CompactReply: true,
		Claims: grant.Claims{
			Version: 3,
			Kind:    "answer",
			Session: strings.Repeat("ab", 32),
			SDP:     strings.Repeat("a=candidate:12345 1 udp 2130706431 192.168.1.10 54321 typ host generation 0\r\n", 25),
		},
	}
	rawJSON, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	legacyPEM := pem.EncodeToMemory(&pem.Block{Type: ticketType, Bytes: rawJSON})
	var compactPEM bytes.Buffer
	if err := writeTicketText(&compactPEM, ticket); err != nil {
		t.Fatal(err)
	}
	if compactPEM.Len() >= len(legacyPEM)/2 {
		t.Fatalf("expected >50%% compression: compact=%d legacy=%d", compactPEM.Len(), len(legacyPEM))
	}
	// Both compressed PEM and legacy uncompressed PEM must decode identically.
	for name, text := range map[string]string{"compressed": compactPEM.String(), "legacy": string(legacyPEM)} {
		got, err := readTicket(text)
		if err != nil || got.Claims.SDP != ticket.Claims.SDP || got.Claims.Session != ticket.Claims.Session {
			t.Fatalf("%s round-trip failed: %v", name, err)
		}
	}
	// Zip-bomb payload decompressing beyond MaxTicketSize must be rejected.
	var bomb bytes.Buffer
	zw := zlib.NewWriter(&bomb)
	_, _ = zw.Write(bytes.Repeat([]byte("A"), grant.MaxTicketSize+1024))
	_ = zw.Close()
	bombPEM := pem.EncodeToMemory(&pem.Block{Type: ticketType, Bytes: bomb.Bytes()})
	if _, err := readTicket(string(bombPEM)); err == nil {
		t.Fatal("accepted oversized decompressed ticket")
	}
	// Non-bracketed paste with leading text on the same line as BEGIN still extracts the ticket.
	prefixed := "邀请文本 " + compactPEM.String() + "next\n"
	r := strings.NewReader(prefixed)
	entry, err := readEntry(r)
	if err != nil || !isTicketText(entry) {
		t.Fatalf("prefixed non-bracketed paste failed: %q, %v", entry, err)
	}
	if got, err := readTicket(entry); err != nil || got.Claims.Session != ticket.Claims.Session {
		t.Fatalf("prefixed paste decoded wrong ticket: %v", err)
	}
	if next, err := readEntry(r); err != nil || next != "next" {
		t.Fatalf("prefixed paste consumed next input: %q, %v", next, err)
	}
}

func TestSignedTicketTextNegotiatesWithLegacyHosts(t *testing.T) {
	host, hostKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	operator, operatorKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	offer, err := grant.NewPairingOffer(hostKey, "offer candidates", "operator", now.Add(time.Hour))
	if err != nil || !offer.CompactReply {
		t.Fatalf("offer does not advertise compact answers: %v", err)
	}
	roundTrip := func(ticket grant.Ticket, compact bool) grant.Ticket {
		t.Helper()
		var out bytes.Buffer
		if err := writeTicketText(&out, ticket); err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(out.Bytes())
		if block == nil || json.Valid(block.Bytes) == compact {
			t.Fatalf("unexpected PEM encoding for %s, compact=%v", ticket.Claims.Kind, compact)
		}
		got, err := readTicket(out.String())
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, supportsCompact := range []bool{false, true} {
		offer.CompactReply = supportsCompact
		received := roundTrip(offer, false)
		if err := received.VerifyOffer(grant.Fingerprint(host), grant.Fingerprint(operator), now); err != nil {
			t.Fatal(err)
		}
		answer, err := grant.NewAnswer(operatorKey, received, strings.Repeat("answer candidates ", 20))
		if err != nil {
			t.Fatal(err)
		}
		if err := roundTrip(answer, supportsCompact).VerifyAnswer(offer, now); err != nil {
			t.Fatal(err)
		}
	}
}

func TestShowPeerIdentityDisplaysFingerprintAndTOFUWarnings(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(t.TempDir(), "device.key")
	fpA := grant.Fingerprint(pubA)

	var out bytes.Buffer
	showPeerIdentity(&out, "被控设备", keyPath, pubA, "Alice's Mac (Lab)")
	text := out.String()
	for _, want := range []string{"Alice's Mac (Lab)", grant.ShortFingerprint(fpA), "首次连接的设备"} {
		if !strings.Contains(text, want) {
			t.Fatalf("first-time output missing %q: %q", want, text)
		}
	}

	if err := grant.RecordPeer(keyPath, fpA, "Alice's Mac (Lab)", time.Now()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	showPeerIdentity(&out, "被控设备", keyPath, pubA, "Alice's Mac (Lab)")
	if !strings.Contains(out.String(), "已知设备") {
		t.Fatalf("known device missing trust record: %q", out.String())
	}

	out.Reset()
	showPeerIdentity(&out, "被控设备", keyPath, pubB, "Alice's Mac (Lab)")
	if !strings.Contains(out.String(), "警告") || !strings.Contains(out.String(), grant.ShortFingerprint(fpA)) {
		t.Fatalf("key mismatch warning missing: %q", out.String())
	}
}

func TestSettingsPersistenceAndCLIOverrides(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "device.key")
	initial := Settings{KeyPath: keyPath, STUN: "stun:custom.example:3478", SSHPort: 2222, TTL: 2 * time.Hour, NoClipboard: true}
	ttl := initial.TTL.String()
	if err := saveSettings(keyPath, persistedSettings{STUN: &initial.STUN, SSHPort: &initial.SSHPort, TTL: &ttl, NoClipboard: &initial.NoClipboard}); err != nil {
		t.Fatal(err)
	}
	loaded := Settings{KeyPath: keyPath, STUN: "auto", SSHPort: 22, TTL: time.Hour}
	applySavedSettings(&loaded)
	if loaded.STUN != initial.STUN || loaded.SSHPort != 2222 || loaded.TTL != 2*time.Hour || !loaded.NoClipboard {
		t.Fatalf("loaded = %+v, want %+v", loaded, initial)
	}
	// Explicitly passed CLI flags must win over settings.json.
	overridden := Settings{
		KeyPath: keyPath, STUN: "none", SSHPort: 2200, TTL: 30 * time.Minute,
		ExplicitSTUN: true, ExplicitSSHPort: true, ExplicitTTL: true, ExplicitNoClipboard: true,
	}
	applySavedSettings(&overridden)
	if overridden.STUN != "none" || overridden.SSHPort != 2200 || overridden.TTL != 30*time.Minute || overridden.NoClipboard {
		t.Fatalf("explicit CLI flags were overwritten: %+v", overridden)
	}
}

func TestClipboardChangePreservesUnrelatedFilesAndSessionOverrides(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "support.key")
	if _, err := grant.NewIdentity(key); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "settings.json")
	original := []byte(`{"application":"other"}`)
	if err := os.WriteFile(foreign, original, 0600); err != nil {
		t.Fatal(err)
	}
	in, out := sshMenuInput(t, "/clipboard\n0\n")
	opts := Settings{KeyPath: key, STUN: "none", ExplicitSTUN: true, TTL: 24 * time.Hour, ExplicitTTL: true, SSHPort: 22, NoClipboard: true}
	if err := Run(t.Context(), opts, in, out); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(foreign); err != nil || !bytes.Equal(data, original) {
		t.Fatal("changed unrelated settings", err)
	}
	var saved persistedSettings
	data, err := os.ReadFile(settingsPath(key))
	if err != nil || json.Unmarshal(data, &saved) != nil || saved.NoClipboard == nil || *saved.NoClipboard || saved.STUN != nil || saved.TTL != nil || saved.SSHPort != nil {
		t.Fatalf("saved runtime overrides: %s (%v)", data, err)
	}
}

func TestParseGrantDurationAcceptsHoursAndSubHourDurations(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"1", time.Hour, true},
		{"24", 24 * time.Hour, true},
		{"15m", 15 * time.Minute, true},
		{"1h30m", 90 * time.Minute, true},
		{"0", 0, false},
		{"25", 0, false},
		{"30s", 0, false},
		{"25h", 0, false},
		{"1.5", 0, false},
	} {
		got, ok := parseGrantDuration(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseGrantDuration(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestTransferSCPAndSFTPArgs(t *testing.T) {
	s := active.State{
		ID:         "grant-9",
		Role:       "control",
		Phase:      "ready",
		Alias:      "peertty-abc",
		User:       "ops",
		Identity:   "/tmp/login.key",
		KnownHosts: "/tmp/known_hosts",
	}
	args, err := scpArgs("/usr/bin/peertty", s, true, []string{":/var/log/app.log", "./app.log"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-r", "StrictHostKeyChecking=yes", "ServerAliveCountMax=5", "ops@peertty-abc:/var/log/app.log", "./app.log"} {
		if !slices.Contains(args, want) {
			t.Fatalf("scpArgs missing %q: %v", want, args)
		}
	}
	// Windows drive letters like C:\file.txt must not be confused with remote paths.
	if got, remote := expandRemoteArg(`C:\Users\alice\log.txt`, s); remote || got != `C:\Users\alice\log.txt` {
		t.Fatalf("Windows path misclassified as remote: %q %v", got, remote)
	}
	if got, remote := expandRemoteArg("remote:/etc/hosts", s); !remote || got != "ops@peertty-abc:/etc/hosts" {
		t.Fatalf("remote: prefix expansion failed: %q %v", got, remote)
	}
	if _, err := scpArgs("/usr/bin/peertty", s, false, []string{"./a", "./b"}); err == nil {
		t.Fatal("accepted scp without any remote path")
	}
	if _, err := scpArgs("/usr/bin/peertty", s, false, []string{":/only-one"}); err == nil {
		t.Fatal("accepted scp with fewer than 2 paths")
	}
	if got, err := scpArgs("/usr/bin/peertty", s, false, []string{":/tmp/file", "report:today.log"}); err != nil || got[len(got)-1] != "."+string(filepath.Separator)+"report:today.log" {
		t.Fatalf("ambiguous local scp destination: %v, %v", got, err)
	}
	sftp := sftpArgs("/usr/bin/peertty", s, []string{"-b", "batch.txt"})
	if sftp[len(sftp)-1] != "ops@peertty-abc" || !slices.Contains(sftp, "-b") || !slices.Contains(sftp, "StrictHostKeyChecking=yes") {
		t.Fatalf("unexpected sftpArgs: %v", sftp)
	}
}

func TestDisplayStatusIncludesRecentWorkerError(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")
	// Without any error record, output stays exact ErrInactive.
	var out bytes.Buffer
	if err := DisplayStatus(t.Context(), key, &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != active.ErrInactive.Error() {
		t.Fatalf("unexpected inactive status: %q", out.String())
	}
	// Simulate a recent abnormal worker exit record.
	rec := `{"error":"批准后 60 秒内未建立直连","at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(key+".last-error", []byte(rec), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := DisplayStatus(t.Context(), key, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "批准后 60 秒内未建立直连") || !strings.Contains(out.String(), "worker.log") {
		t.Fatalf("expected recent error and log path in status: %q", out.String())
	}
}

func TestRunTransferAndHelperEdgeCases(t *testing.T) {
	if (reconnectingGrant{id: "x"}).Error() != reconnectNotice {
		t.Fatal("unexpected reconnectingGrant error text")
	}
	if ttlLabel(90*time.Minute) != "1h30m0s" || ttlLabel(2*time.Hour) != "2 小时" {
		t.Fatalf("unexpected ttlLabel: %q %q", ttlLabel(90*time.Minute), ttlLabel(2*time.Hour))
	}
	if p, err := userPath(`"~/foo"`); err != nil || !strings.HasSuffix(p, filepath.Join("foo")) {
		t.Fatalf("userPath quoted tilde: %q %v", p, err)
	}
	// Corrupted settings.json must be ignored without panicking or mutating defaults.
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("{invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	opts := Settings{KeyPath: key, STUN: "auto", SSHPort: 22, TTL: time.Hour}
	applySavedSettings(&opts)
	if opts.STUN != "auto" || opts.SSHPort != 22 {
		t.Fatalf("corrupted settings mutated defaults: %+v", opts)
	}
	// Exercise runTransfer with a stubbed command runner.
	if _, err := os.Stat("/usr/bin/scp"); err == nil {
		st := active.State{ID: "grant-42", Role: "control", Phase: "ready", Alias: "peertty-123", User: "ops"}
		var gotArgs, gotEnv []string
		err := runTransfer(t.Context(), key, st, nil, &bytes.Buffer{}, &bytes.Buffer{}, "scp", func(exe string) ([]string, error) {
			return scpArgs(exe, st, false, []string{":/tmp/a", "./a"})
		}, func(cmd *exec.Cmd) error {
			gotArgs, gotEnv = cmd.Args, cmd.Env
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(gotEnv, "PEERTTY_LINK_KEY="+key) || !slices.Contains(gotEnv, "PEERTTY_LINK_ID=grant-42") {
			t.Fatalf("missing grant env in scp: %v", gotEnv)
		}
		if !slices.Contains(gotArgs, "ops@peertty-123:/tmp/a") {
			t.Fatalf("missing expanded remote path in scp args: %v", gotArgs)
		}
	}
	// Exercise handleHostEnded for expired, last-error, and normal end paths.
	var out bytes.Buffer
	c := Console{Settings: Settings{KeyPath: key}, out: &out}
	if err := c.handleHostEnded(t.Context(), active.State{ID: "g1", Deadline: time.Now().Add(time.Hour)}, active.ErrInactive); err != nil || !strings.Contains(out.String(), "被控会话已结束") {
		t.Fatalf("normal end: err=%v out=%q", err, out.String())
	}
	rec := `{"error":"对端未响应","at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(key+".last-error", []byte(rec), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.handleHostEnded(t.Context(), active.State{ID: "g1", Deadline: time.Now().Add(time.Hour)}, active.ErrInactive); err == nil || !strings.Contains(err.Error(), "对端未响应") {
		t.Fatalf("last-error end: err=%v", err)
	}
}
