package console

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"peertty/internal/identitystate"
)

func putSettingsFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := identitystate.EnsureDir(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSavedSettingsValidateFieldsIndependently(t *testing.T) {
	for _, tc := range []struct {
		name, raw, stun       string
		port                  int
		ttl                   time.Duration
		noClipboard, explicit bool
	}{
		{name: "valid nondefaults", raw: `{"stun":"none","ssh_port":65535,"ttl":"24h","no_clipboard":true}`, stun: "none", port: 65535, ttl: 24 * time.Hour, noClipboard: true},
		{name: "bad STUN does not lose port", raw: `{"stun":"turn:example.invalid","ssh_port":2222,"ttl":"45m"}`, stun: "auto", port: 2222, ttl: 45 * time.Minute},
		{name: "port below range", raw: `{"ssh_port":0,"ttl":"0s","no_clipboard":true}`, stun: "auto", port: 22, ttl: time.Hour, noClipboard: true},
		{name: "port above range", raw: `{"ssh_port":65536,"ttl":"25h"}`, stun: "auto", port: 22, ttl: time.Hour},
		{name: "unparseable time", raw: `{"ttl":"later"}`, stun: "auto", port: 22, ttl: time.Hour},
		{name: "explicit flags win", raw: `{"stun":"none","ssh_port":2345,"ttl":"90m","no_clipboard":true}`, stun: "auto", port: 22, ttl: time.Hour, explicit: true},
		{name: "damaged file", raw: "{bad", stun: "auto", port: 22, ttl: time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := filepath.Join(t.TempDir(), "device.key")
			path := settingsPath(key)
			putSettingsFixture(t, path, tc.raw)
			got := Settings{KeyPath: key, STUN: "auto", SSHPort: 22, TTL: time.Hour,
				ExplicitSTUN: tc.explicit, ExplicitTTL: tc.explicit, ExplicitSSHPort: tc.explicit, ExplicitNoClipboard: tc.explicit}
			applySavedSettings(&got)
			if got.STUN != tc.stun || got.SSHPort != tc.port || got.TTL != tc.ttl || got.NoClipboard != tc.noClipboard {
				t.Fatalf("settings = %+v", got)
			}
		})
	}
	o := Settings{KeyPath: "relative.key", STUN: "auto", TTL: time.Hour}
	applySavedSettings(&o)
	if o.STUN != "auto" || o.TTL != time.Hour {
		t.Fatal("relative key altered user defaults")
	}
}

func TestLegacySettingsImportDoesNotAdoptUnknownOrEmptyConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		imported  bool
	}{
		{"supported", `{"no_clipboard":false,"ssh_port":2222}`, true},
		{"unknown keys", `{"outside_schema":true,"ssh_port":2222}`, false},
		{"empty", `{}`, false},
		{"malformed", `{`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(dir, "key")
			legacy := filepath.Join(dir, "settings.json")
			putSettingsFixture(t, legacy, tc.raw)
			if err := importDirectorySettings(key); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(settingsPath(key))
			if tc.imported {
				if err != nil || string(data) != tc.raw {
					t.Fatalf("import = %q %v", data, err)
				}
				port := 2200
				if err := saveSettings(key, persistedSettings{SSHPort: &port}); err != nil {
					t.Fatal(err)
				}
				if err := importDirectorySettings(key); err != nil {
					t.Fatal(err)
				}
				o := Settings{KeyPath: key}
				applySavedSettings(&o)
				if o.SSHPort != 2200 {
					t.Fatalf("import overwrote current state: %+v", o)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unrecognized legacy data was imported: %v", err)
			}
			raw, err := os.ReadFile(legacy)
			if err != nil || string(raw) != tc.raw {
				t.Fatalf("legacy data changed: %v", err)
			}
		})
	}
}

func TestSettingsSaveDoesNotReplaceMalformedFile(t *testing.T) {
	key := filepath.Join(t.TempDir(), "key")
	path := settingsPath(key)
	const malformed = "\"settings are not an object\""
	putSettingsFixture(t, path, malformed)
	port := 2222
	if err := saveSettings(key, persistedSettings{SSHPort: &port}); err == nil {
		t.Fatal("overwrote malformed settings")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, []byte(malformed)) {
		t.Fatalf("settings replaced: %q / %v", got, err)
	}
	key = filepath.Join(t.TempDir(), "empty.key")
	if err := saveSettings(key, persistedSettings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(settingsPath(key)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty update created settings: %v", err)
	}
}
