package console

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"peertty/internal/bridge"
	"peertty/internal/filelock"
)

// OpenSSH starts the proxy as a grandchild. These two OS-owned leases let the
// proxy observe a dead menu even while it is waiting for a human's approval.
func (h handoff) workerPath() string { return filepath.Join(filepath.Dir(h.Offer), "worker") }

func held(path string) (bool, error) {
	f, err := filelock.Try(path)
	if errors.Is(err, filelock.ErrBusy) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, f.Close()
}

func (h handoff) runSSH(cmd *exec.Cmd) error {
	if err := os.WriteFile(h.workerPath(), nil, 0600); err != nil {
		return err
	}
	owner, err := filelock.Try(h.Offer)
	if err != nil {
		return err
	}
	runErr := cmd.Run()
	owner.Close()
	// The worker releases the device identity before releasing its marker.
	limit := time.NewTimer(bridge.ProxyDrainTimeout + 2*time.Second)
	defer limit.Stop()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	for {
		busy, err := held(h.workerPath())
		if err != nil || !busy {
			return errors.Join(runErr, err)
		}
		select {
		case <-tick.C:
		case <-limit.C:
			return errors.Join(runErr, errors.New("SSH 代理退出超时，设备仍受原授权锁保护"))
		}
	}
}

func (h handoff) watchMenu(ctx context.Context, cancel context.CancelFunc, connected <-chan struct{}) {
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if busy, err := held(h.Offer); err == nil && busy {
			continue
		}
		select {
		case <-connected:
			// Allow an established SSH session to finish its ordered FIN/ACK.
			timer := time.NewTimer(bridge.ProxyDrainTimeout)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		default:
		}
		cancel()
		return
	}
}
