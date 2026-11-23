package console

import (
	"bytes"
	"encoding/json"
	"time"

	"peertty/internal/grant"
	"peertty/internal/identitystate"
	"peertty/internal/transport"
)

func importDirectorySettings(key string) error {
	return identitystate.ImportLegacy(key, "settings.json", maxSettingsFile, func(data []byte) bool {
		var settings persistedSettings
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		return json.Valid(data) && dec.Decode(&settings) == nil && settings != (persistedSettings{})
	})
}

const maxSettingsFile = 16 * 1024

type persistedSettings struct {
	STUN        *string `json:"stun,omitempty"`
	SSHPort     *int    `json:"ssh_port,omitempty"`
	TTL         *string `json:"ttl,omitempty"`
	NoClipboard *bool   `json:"no_clipboard,omitempty"`
}

func settingsPath(keyPath string) string {
	return identitystate.Path(keyPath, "settings.json")
}

// applySavedSettings loads persisted user defaults from settings.json alongside
// the device key without overriding flags explicitly supplied on the CLI.
func applySavedSettings(opts *Settings) {
	path := settingsPath(opts.KeyPath)
	if path == "" {
		return
	}
	data, err := identitystate.Read(path, maxSettingsFile)
	if err != nil {
		return
	}
	var saved persistedSettings
	if err := json.Unmarshal(data, &saved); err != nil {
		return
	}
	if !opts.ExplicitSTUN && saved.STUN != nil {
		if _, err := transport.STUNServers(*saved.STUN); err == nil {
			opts.STUN = *saved.STUN
		}
	}
	if !opts.ExplicitSSHPort && saved.SSHPort != nil && *saved.SSHPort >= 1 && *saved.SSHPort <= 65535 {
		opts.SSHPort = *saved.SSHPort
	}
	if !opts.ExplicitTTL && saved.TTL != nil {
		if d, err := time.ParseDuration(*saved.TTL); err == nil && d > 0 && d <= grant.MaxTTL {
			opts.TTL = d
		}
	}
	if !opts.ExplicitNoClipboard && saved.NoClipboard != nil {
		opts.NoClipboard = *saved.NoClipboard
	}
}

func saveSettings(keyPath string, changes persistedSettings) error {
	path := settingsPath(keyPath)
	if path == "" || changes == (persistedSettings{}) {
		return nil
	}
	return identitystate.Update(path, maxSettingsFile, func(data []byte) ([]byte, error) {
		var saved persistedSettings
		if data != nil {
			if err := json.Unmarshal(data, &saved); err != nil {
				return nil, err
			}
		}
		if changes.STUN != nil {
			saved.STUN = changes.STUN
		}
		if changes.SSHPort != nil {
			saved.SSHPort = changes.SSHPort
		}
		if changes.NoClipboard != nil {
			saved.NoClipboard = changes.NoClipboard
		}
		if changes.TTL != nil {
			saved.TTL = changes.TTL
		}
		return json.MarshalIndent(saved, "", "  ")
	})
}
