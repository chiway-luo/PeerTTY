package console

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"peertty/internal/grant"
	"peertty/internal/transport"
)

const maxSettingsFile = 16 * 1024

type persistedSettings struct {
	STUN        *string `json:"stun,omitempty"`
	SSHPort     *int    `json:"ssh_port,omitempty"`
	TTL         *string `json:"ttl,omitempty"`
	NoClipboard *bool   `json:"no_clipboard,omitempty"`
}

func settingsPath(keyPath string) string {
	if keyPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(keyPath), "settings.json")
}

// applySavedSettings loads persisted user defaults from settings.json alongside
// the device key without overriding flags explicitly supplied on the CLI.
func applySavedSettings(opts *Settings) {
	path := settingsPath(opts.KeyPath)
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxSettingsFile {
		return
	}
	data, err := os.ReadFile(path)
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

func saveSettings(opts Settings) error {
	path := settingsPath(opts.KeyPath)
	if path == "" {
		return nil
	}
	stun := opts.STUN
	port := opts.SSHPort
	noClip := opts.NoClipboard
	payload := persistedSettings{
		STUN:        &stun,
		SSHPort:     &port,
		NoClipboard: &noClip,
	}
	if opts.TTL > 0 && opts.TTL <= grant.MaxTTL {
		ttl := opts.TTL.String()
		payload.TTL = &ttl
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".peertty-settings-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, wErr := tmp.Write(data)
	if err := errors.Join(wErr, tmp.Close()); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
