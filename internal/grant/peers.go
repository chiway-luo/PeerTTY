package grant

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxKnownPeersFile = 256 * 1024

type PeerTrust int

const (
	PeerNew PeerTrust = iota
	PeerKnown
	PeerKeyMismatch
)

// PeerRecord stores a previously approved or contacted device fingerprint for TOFU.
type PeerRecord struct {
	Name      string    `json:"name,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// PeerCheck summarizes the TOFU comparison for a peer presenting a ticket.
type PeerCheck struct {
	Trust        PeerTrust
	PreviousName string
	LastSeen     time.Time
	ConflictID   string
}

func peersPath(keyPath string) string {
	if keyPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(keyPath), "known_peers.json")
}

func loadPeers(path string) (map[string]PeerRecord, error) {
	if path == "" {
		return nil, nil
	}
	data, err := readLimited(path, maxKnownPeersFile)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]PeerRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var peers map[string]PeerRecord
	if err := json.Unmarshal(data, &peers); err != nil {
		return nil, err
	}
	if peers == nil {
		peers = map[string]PeerRecord{}
	}
	return peers, nil
}

// LookupPeer checks whether the device fingerprint has been seen before, or
// whether another key previously presented the same device name.
func LookupPeer(keyPath, fingerprint, deviceName string) PeerCheck {
	if !ValidFingerprint(fingerprint) {
		return PeerCheck{Trust: PeerNew}
	}
	peers, err := loadPeers(peersPath(keyPath))
	if err != nil || len(peers) == 0 {
		return PeerCheck{Trust: PeerNew}
	}
	if rec, ok := peers[fingerprint]; ok {
		return PeerCheck{
			Trust:        PeerKnown,
			PreviousName: rec.Name,
			LastSeen:     rec.LastSeen,
		}
	}
	trimmed := strings.TrimSpace(deviceName)
	if trimmed != "" {
		for fp, rec := range peers {
			if strings.EqualFold(strings.TrimSpace(rec.Name), trimmed) {
				return PeerCheck{
					Trust:      PeerKeyMismatch,
					ConflictID: ShortFingerprint(fp),
					LastSeen:   rec.LastSeen,
				}
			}
		}
	}
	return PeerCheck{Trust: PeerNew}
}

// RecordPeer saves or updates a verified device fingerprint in the state directory.
func RecordPeer(keyPath, fingerprint, deviceName string, now time.Time) error {
	path := peersPath(keyPath)
	if path == "" || !ValidFingerprint(fingerprint) {
		return nil
	}
	peers, err := loadPeers(path)
	if err != nil {
		// Do not lose future trust tracking if a corrupted file exists.
		peers = map[string]PeerRecord{}
	}
	rec, ok := peers[fingerprint]
	if !ok {
		rec.FirstSeen = now.UTC()
	}
	if name := strings.TrimSpace(deviceName); name != "" {
		rec.Name = name
	}
	rec.LastSeen = now.UTC()
	peers[fingerprint] = rec

	data, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".peertty-peers-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, writeErr := tmp.Write(data)
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
