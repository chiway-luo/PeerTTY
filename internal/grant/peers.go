package grant

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"peertty/internal/identitystate"
)

const maxKnownPeersFile = 16 * 1024 * 1024

type PeerTrust int

const (
	PeerNew PeerTrust = iota
	PeerKnown
	PeerKeyMismatch
	PeerHistoryUnavailable
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
	return identitystate.Path(keyPath, "known_peers.json")
}

func decodePeers(data []byte) (map[string]PeerRecord, error) {
	peers := map[string]PeerRecord{}
	if data != nil {
		if err := json.Unmarshal(data, &peers); err != nil {
			return nil, err
		}
		if peers == nil {
			return nil, errors.New("设备信任记录格式无效")
		}
		for fp, rec := range peers {
			if !ValidFingerprint(fp) || rec.FirstSeen.IsZero() || rec.LastSeen.IsZero() {
				return nil, errors.New("设备信任记录缺少有效指纹或连接时间")
			}
		}
	}
	return peers, nil
}

func ImportDirectoryPeers(key string) error {
	return identitystate.ImportLegacy(key, "known_peers.json", maxKnownPeersFile, func(data []byte) bool {
		peers, err := decodePeers(data)
		return err == nil && len(peers) != 0
	})
}

// LookupPeer checks whether the device fingerprint has been seen before, or
// whether another key previously presented the same device name.
func LookupPeer(keyPath, fingerprint, deviceName string) PeerCheck {
	if !ValidFingerprint(fingerprint) {
		return PeerCheck{Trust: PeerNew}
	}
	path := peersPath(keyPath)
	if path == "" {
		return PeerCheck{Trust: PeerNew}
	}
	data, err := identitystate.Read(path, maxKnownPeersFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return PeerCheck{Trust: PeerHistoryUnavailable}
	}
	peers, err := decodePeers(data)
	if err != nil {
		return PeerCheck{Trust: PeerHistoryUnavailable}
	}
	if len(peers) == 0 {
		return PeerCheck{Trust: PeerNew}
	}
	rec, known := peers[fingerprint]
	trimmed := strings.TrimSpace(deviceName)
	if trimmed != "" && (!known || !strings.EqualFold(strings.TrimSpace(rec.Name), trimmed)) {
		var conflictID string
		var lastSeen time.Time
		for fp, other := range peers {
			if strings.EqualFold(strings.TrimSpace(other.Name), trimmed) &&
				(conflictID == "" || other.LastSeen.After(lastSeen) || (other.LastSeen.Equal(lastSeen) && fp < conflictID)) {
				conflictID, lastSeen = fp, other.LastSeen
			}
		}
		if conflictID != "" {
			return PeerCheck{Trust: PeerKeyMismatch, ConflictID: ShortFingerprint(conflictID), LastSeen: lastSeen}
		}
	}
	if known {
		return PeerCheck{Trust: PeerKnown, PreviousName: rec.Name, LastSeen: rec.LastSeen}
	}
	return PeerCheck{Trust: PeerNew}
}

// RecordPeer saves or updates a verified device fingerprint in the state directory.
func RecordPeer(keyPath, fingerprint, deviceName string, now time.Time) error {
	path := peersPath(keyPath)
	if path == "" || !ValidFingerprint(fingerprint) {
		return nil
	}
	return identitystate.Update(path, maxKnownPeersFile, func(data []byte) ([]byte, error) {
		peers, err := decodePeers(data)
		if err != nil {
			return nil, err
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

		return json.MarshalIndent(peers, "", "  ")
	})
}
