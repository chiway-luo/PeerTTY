package transport

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pion/webrtc/v4"
)

func TestSelectedRouteReportsOnlyDirectPairs(t *testing.T) {
	host := webrtc.ICECandidateTypeHost
	mapped := webrtc.ICECandidateTypeSrflx
	relay := webrtc.ICECandidateTypeRelay
	for _, tc := range []struct {
		name            string
		local, remote   webrtc.ICECandidateType
		selectionError  error
		want, wantError string
	}{
		{name: "established direct route", local: host, remote: mapped, want: "udp host/srflx"},
		{name: "local relay refused", local: relay, remote: host, wantError: "relayed path rejected"},
		{name: "remote relay refused", local: host, remote: relay, wantError: "relayed path rejected"},
		{name: "no selected route", wantError: "no selected ICE candidate pair"},
		{name: "selection failed", local: host, remote: host, selectionError: errors.New("fixture ICE selection failure"), wantError: "no selected ICE candidate pair"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pair *webrtc.ICECandidatePair
			if tc.local != webrtc.ICECandidateTypeUnknown {
				pair = webrtc.NewICECandidatePair(
					&webrtc.ICECandidate{Typ: tc.local, Protocol: webrtc.ICEProtocolUDP},
					&webrtc.ICECandidate{Typ: tc.remote, Protocol: webrtc.ICEProtocolUDP})
			}
			route, err := directRoute(pair, tc.selectionError)
			if route != tc.want || tc.wantError == "" && err != nil || tc.wantError != "" && (err == nil || err.Error() != tc.wantError) {
				t.Fatalf("route=%q error=%v, want %q / %q", route, err, tc.want, tc.wantError)
			}
		})
	}
}

func TestPeerStateKeepsOnlyRecoverableGrantsAlive(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    peerMode
		state   webrtc.PeerConnectionState
		stopped bool
	}{
		{"single session lost path", singleSession, webrtc.PeerConnectionStateDisconnected, true},
		{"reusable grant waits for route recovery", reusableSession, webrtc.PeerConnectionStateDisconnected, false},
		{"reusable grant cannot recover failed connection", reusableSession, webrtc.PeerConnectionStateFailed, true},
		{"closed connection ends grant", reusableSession, webrtc.PeerConnectionStateClosed, true},
		{"connecting does not close the grant", reusableSession, webrtc.PeerConnectionStateConnecting, false},
		{"connected does not close the grant", singleSession, webrtc.PeerConnectionStateConnected, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lifetime, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			refresh, stop := context.WithCancel(t.Context())
			defer stop()
			reportConnectionState(tc.mode, tc.state, stop, cancel)
			cause := context.Cause(lifetime)
			if (cause != nil) != tc.stopped || (refresh.Err() != nil) != tc.stopped {
				t.Fatalf("grant=%v, refresh=%v, want stopped=%t", cause, refresh.Err(), tc.stopped)
			}
			if tc.stopped && !strings.Contains(cause.Error(), tc.state.String()) {
				t.Fatalf("connection state obscured: %v", cause)
			}
		})
	}
}
