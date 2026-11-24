package localssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestGuardShutdownEscalatesOnlyAfterGracePeriod(t *testing.T) {
	for _, stuck := range []bool{false, true} {
		t.Run(fmt.Sprintf("stuck=%t", stuck), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				input := new(countedInput)
				waitErr, killErr := errors.New("fixture wait error"), errors.New("fixture process signal error")
				g := &guard{input: input, done: make(chan struct{})}
				start := time.Now()
				calls := 0
				err := g.closeWith(func() error {
					calls++
					if got := time.Since(start); got != 4*time.Second || input.closes != 1 {
						t.Fatalf("escalated at %s with %d pipe closes", got, input.closes)
					}
					if !stuck {
						g.err = waitErr
						close(g.done)
					}
					return killErr
				})
				if calls != 1 || !errors.Is(err, killErr) {
					t.Fatalf("kill calls=%d, err=%v", calls, err)
				}
				if stuck {
					if time.Since(start) != 6*time.Second || !strings.Contains(err.Error(), "未在规定时间内退出") {
						t.Fatalf("stalled process surfaced as %v after %s", err, time.Since(start))
					}
				} else if time.Since(start) != 4*time.Second || !errors.Is(err, waitErr) {
					t.Fatalf("exit cause lost: %v after %s", err, time.Since(start))
				}
			})
		})
	}
}

func TestOwnershipConfirmationStopsWhileWaiting(t *testing.T) {
	for _, exited := range []bool{false, true} {
		t.Run(fmt.Sprintf("exited=%t", exited), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, stop := context.WithCancel(t.Context())
				defer stop()
				done := make(chan struct{})
				result := make(chan error, 1)
				queries := 0
				go func() {
					result <- waitForOwnedConnection(ctx, done, nil, func() (bool, error) {
						queries++
						return false, nil
					})
				}()
				synctest.Wait()
				if queries != 1 {
					t.Fatalf("expected one pending ownership check, got %d", queries)
				}
				if exited {
					close(done)
					if err := <-result; err == nil || !strings.Contains(err.Error(), "退出") {
						t.Fatalf("exit reported as %v", err)
					}
				} else {
					stop()
					if err := <-result; !errors.Is(err, context.Canceled) {
						t.Fatalf("cancel reported as %v", err)
					}
				}
			})
		})
	}
}

func TestGuardPrivateParentChannelLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, mode, text string
		port             int
	}{
		{"plain startup at lower boundary", "", "1\n", 1},
		{"scoped open at upper boundary", "login-open", "65535\n", 65535},
		{"scoped closed", "login-closed", "4222\n", 4222},
		{"parent EOF", "", "", 0},
		{"not a port", "", "none\n", 0},
		{"zero is not a connected port", "", "0\n", 0},
		{"out of range", "", "65536\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				in, parent := io.Pipe()
				defer in.Close()
				defer parent.Close()
				out := io.Discard
				deadline := time.Now().Add(time.Minute)
				args := []string{strconv.FormatInt(deadline.UnixMilli(), 10)}
				var dir string
				if tc.mode != "" {
					dir = "fixture-directory"
					args = append(args, tc.mode, dir)
				}
				result := make(chan error, 1)
				go func() {
					result <- serveWith(t.Context(), args, in, out, func(ctx context.Context, ports <-chan int, ready io.Writer, mode, path string) error {
						gotDeadline, ok := ctx.Deadline()
						if !ok || !gotDeadline.Equal(deadline) || ready != out || mode != tc.mode || path != dir {
							t.Errorf("wrong guard setup: %v %t %q %q", gotDeadline, ok, mode, path)
						}
						if tc.port != 0 {
							n := <-ports
							if n != tc.port || ctx.Err() != nil {
								t.Errorf("wrong live parent port: %d (%v)", n, ctx.Err())
							}
						}
						<-ctx.Done()
						select {
						case n := <-ports:
							t.Errorf("unexpected extra port: %d", n)
						default:
						}
						return ctx.Err()
					})
				}()
				synctest.Wait()
				if tc.text != "" {
					if _, err := io.WriteString(parent, tc.text); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
				}
				if tc.port != 0 {
					select {
					case err := <-result:
						t.Fatalf("live parent closed prematurely: %v", err)
					default:
					}
				}
				if err := parent.Close(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, context.Canceled) {
					t.Fatalf("parent termination: %v", err)
				}
			})
		})
	}
}
