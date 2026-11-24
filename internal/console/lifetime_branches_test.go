package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"peertty/internal/bridge"
	"peertty/internal/filelock"
)

func TestHandoffDistinguishesMissingAndBusyLeases(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	if busy, err := held(missing); busy || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing lease: busy=%v err=%v", busy, err)
	}
	offer := filepath.Join(dir, "offer")
	if err := os.WriteFile(offer, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	owner, err := filelock.Try(offer)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if busy, err := held(offer); !busy || err != nil {
		t.Fatalf("held lease: busy=%v err=%v", busy, err)
	}
	h := handoff{Offer: offer}
	if err := h.runSSH(nil); !errors.Is(err, filelock.ErrBusy) {
		t.Fatalf("launcher proceeded despite offer lock: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if busy, err := held(offer); busy || err != nil {
		t.Fatalf("released lease: busy=%v err=%v", busy, err)
	}
	h.Offer = filepath.Join(missing, "offer")
	if err := h.runSSH(nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("launcher proceeded without a worker marker directory: %v", err)
	}
}

func TestWatchMenuCancelsPendingPairingWhenOwnerDisappears(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	h := handoff{Offer: filepath.Join(dir, "missing-offer")}
	stopped := make(chan struct{})
	go func() { defer close(stopped); h.watchMenu(ctx, cancel, make(chan struct{})) }()
	select {
	case <-stopped:
	case <-ctx.Done():
		<-stopped
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("missing offer did not cancel pending pairing: %v", ctx.Err())
	}
}

func TestWatchMenuPreservesEstablishedStreamForBoundedDrain(t *testing.T) {
	for _, stopEarly := range []bool{false, true} {
		label := "grace elapsed"
		if stopEarly {
			label = "owner canceled during grace"
		}
		t.Run(label, func(t *testing.T) {
			offer := filepath.Join(t.TempDir(), "offer")
			if err := os.WriteFile(offer, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				owner, err := filelock.Try(offer)
				if err != nil {
					t.Fatal(err)
				}
				defer owner.Close()
				ctx, stop := context.WithCancel(t.Context())
				defer stop()
				connected := make(chan struct{})
				close(connected)
				stopped := make(chan struct{})
				canceled := make(chan struct{}, 1)
				h := handoff{Offer: offer}
				go func() {
					defer close(stopped)
					h.watchMenu(ctx, func() { canceled <- struct{}{} }, connected)
				}()
				synctest.Wait()
				time.Sleep(350 * time.Millisecond)
				synctest.Wait()
				select {
				case <-stopped:
					t.Fatal("active menu was reported closed while lease was held")
				default:
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				time.Sleep(300 * time.Millisecond)
				synctest.Wait()
				time.Sleep(bridge.ProxyDrainTimeout - time.Second)
				select {
				case <-canceled:
					t.Fatal("established session was canceled before drain grace")
				default:
				}
				if stopEarly {
					stop()
				} else {
					time.Sleep(time.Second)
				}
				<-stopped
				gotCanceled := len(canceled) != 0
				if gotCanceled == stopEarly {
					t.Fatalf("wrong cancellation at exit: %v (stopped early=%v)", gotCanceled, stopEarly)
				}
			})
		})
	}
}
