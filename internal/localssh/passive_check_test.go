package localssh

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
)

func TestPassiveProbeDistinguishesSSHFromAnotherLocalService(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		ready          bool
	}{
		{"current SSH", "notice\r\nSSH-2.0-fixture\r\n", true},
		{"compatible SSH", "SSH-1.99-fixture\r\n", true},
		{"unsupported version", "SSH-1.5-fixture\r\n", false},
		{"other service", "HTTP/1.1 200 OK\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := listener.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.WriteString(c, tc.response)
			}()
			defer func() { listener.Close(); <-done }()
			got := CheckHost(t.Context(), port)
			if got.Ready != tc.ready || got.Closed || got.Apply != nil {
				t.Fatalf("service %s: %+v", tc.name, got)
			}
		})
	}
}

func TestPassiveProbeCancellationIsNotReportedAsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := ProbeListener(ctx, 1); got.Ready || got.Closed || !strings.Contains(got.Message, "无法检查") || got.Detail == "" {
		t.Fatalf("canceled check reported incorrect state: %+v", got)
	}
}

func TestBannerReadStopsAtLimitOrShortEOF(t *testing.T) {
	for _, body := range []string{
		"SSH-2.0-fixture",
		strings.Repeat("x", 8192) + "\nSSH-2.0-fixture\n",
	} {
		if hasSSHBanner(strings.NewReader(body)) {
			t.Fatal("incomplete or out-of-budget banner was accepted")
		}
	}
}
