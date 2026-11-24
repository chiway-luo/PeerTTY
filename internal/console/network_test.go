package console

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"peertty/internal/transport"
)

func TestNetworkCheckReportsOnlyObservedMappings(t *testing.T) {
	const server = "stun:192.0.2.4:3478"
	probe := func(endpoint, mapped string) transport.MappingProbe {
		return transport.MappingProbe{
			Server: server, Endpoint: netip.MustParseAddrPort(endpoint),
			Mapped: netip.MustParseAddrPort(mapped),
		}
	}
	first := probe("192.0.2.4:3478", "203.0.113.1:5000")
	second := probe("192.0.2.5:3478", "203.0.113.1:5001")
	failed := first
	failed.Err = errors.New("no response")
	candErr := errors.New("candidate collection failed")
	for _, tc := range []struct {
		name, spec          string
		mapped              int
		probes              []transport.MappingProbe
		discovered, require bool
		candErr             error
		wants, omitted      []string
		wantErr             string
	}{
		{name: "invalid input", spec: "turn:example.test", wantErr: "STUN"},
		{name: "candidate failure", spec: "none", candErr: candErr, wantErr: "candidate collection failed",
			wants: []string{"网络自检 · STUN 已关闭"}, omitted: []string{"仅探测接口地址"}},
		{name: "STUN disabled", spec: "none", wants: []string{"仅探测接口地址"}, omitted: []string{"路由器 UPnP"}},
		{name: "mapping required with STUN disabled", spec: "none", require: true, wantErr: "本次自检未取得 STUN 映射"},
		{name: "mapping from ICE", spec: server, mapped: 1, require: true,
			wants: []string{"路由器 UPnP · 未发现", "已取得 STUN 映射。"}, omitted: []string{"NAT 类型"}},
		{name: "mapping from probe", spec: server, require: true, discovered: true,
			probes: []transport.MappingProbe{first, failed, {}},
			wants:  []string{"路由器 UPnP · 已发现 router.example", "NAT 类型", "已取得 STUN 映射。"}},
		{name: "port dependence", spec: server, require: true,
			probes: []transport.MappingProbe{first, second},
			wants:  []string{"端口随目的地变化"}},
		{name: "failed probe is not a mapping", spec: server, require: true,
			probes: []transport.MappingProbe{failed}, wantErr: "本次自检未取得 STUN 映射",
			wants: []string{"NAT 类型", "未取得 STUN 映射。请检查"}, omitted: []string{"已取得 STUN 映射"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var called atomic.Int32
			ctx := t.Context()
			checks := networkChecks{
				candidates: func(got context.Context, spec string) (transport.Candidates, error) {
					if got != ctx || spec != tc.spec {
						t.Error("candidate check received wrong parameters")
					}
					called.Add(1)
					return transport.Candidates{Mapped: tc.mapped}, tc.candErr
				},
				nat: func(got context.Context, spec string) (transport.NATReport, error) {
					if got != ctx || spec != tc.spec {
						t.Error("NAT check received wrong parameters")
					}
					called.Add(2)
					return transport.NATReport{Probes: tc.probes}, nil
				},
				upnp: func(got context.Context) (string, bool) {
					if got != ctx {
						t.Error("UPnP check received wrong context")
					}
					called.Add(4)
					return "router.example", tc.discovered
				},
			}
			var out bytes.Buffer
			err := checks.run(ctx, &out, tc.spec, tc.require)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want %q; output %q", err, tc.wantErr, out.String())
			}
			for _, part := range tc.wants {
				if !strings.Contains(out.String(), part) {
					t.Errorf("missing %q from %q", part, out.String())
				}
			}
			for _, part := range tc.omitted {
				if strings.Contains(out.String(), part) {
					t.Errorf("unexpected %q in %q", part, out.String())
				}
			}
			wantCalled := map[string]int32{"none": 1, server: 7}[tc.spec]
			if got := called.Load(); got != wantCalled {
				t.Fatalf("probe set = %d, want %d", got, wantCalled)
			}
		})
	}
}
