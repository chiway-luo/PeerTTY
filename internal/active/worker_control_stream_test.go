package active

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type fixtureGrantControlStream struct {
	input    string
	text     bool
	readErr  error
	writeErr error
	deadline time.Time
	output   string
	sentText bool
}

func (s *fixtureGrantControlStream) ReadDataChannel(buf []byte) (int, bool, error) {
	return copy(buf, s.input), s.text, s.readErr
}

func (s *fixtureGrantControlStream) WriteDataChannel(buf []byte, text bool) (int, error) {
	s.output, s.sentText = string(buf), text
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return len(buf), nil
}

func (s *fixtureGrantControlStream) SetWriteDeadline(deadline time.Time) error {
	s.deadline = deadline
	return nil
}

func TestGrantControlClosure(t *testing.T) {
	for _, tc := range []struct {
		name, input, want     string
		text, cancel, revoked bool
		readErr, writeErr     error
	}{
		{name: "acknowledge peer revocation", input: "REVOKE", text: true, revoked: true},
		{name: "revoke remains final if ack cannot be delivered", input: "REVOKE", text: true, revoked: true, writeErr: io.ErrClosedPipe},
		{name: "closed confirms local termination", input: "CLOSED", text: true, cancel: true},
		{name: "unprompted closure status not treated as confirmation", input: "CLOSED", text: true, want: "未知的授权状态"},
		{name: "channel ended without a final status", readErr: io.EOF, want: "授权状态通道已关闭"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			wire := &fixtureGrantControlStream{input: tc.input, text: tc.text, readErr: tc.readErr, writeErr: tc.writeErr}
			calls := 0
			err := readGrantClosure(ctx, wire, func() { calls++ })
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if tc.readErr != nil && !errors.Is(err, tc.readErr) {
				t.Fatalf("underlying stream error lost: %v", err)
			}
			if tc.revoked {
				if calls != 1 || wire.output != "CLOSED" || !wire.sentText || wire.deadline.IsZero() {
					t.Fatalf("revocation not acknowledged with bounded text write: calls=%d, stream=%+v", calls, wire)
				}
			} else if calls != 0 || wire.output != "" || !wire.deadline.IsZero() {
				t.Fatalf("non-revocation generated an acknowledgment: calls=%d, stream=%+v", calls, wire)
			}
		})
	}
}
