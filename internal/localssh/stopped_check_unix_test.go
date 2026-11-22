//go:build darwin || linux

package localssh

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestStoppedSSHChecksWithoutMachineSideEffects(t *testing.T) {
	busy := errors.New("fixture address unavailable")
	bad := errors.New("fixture sshd failed")
	for _, tc := range []struct {
		name               string
		stat, bind, config error
		euid               int
		guard, cancel      bool
		log, want          string
		wantReady          bool
		calls              string
	}{
		{name: "missing server", stat: os.ErrNotExist, want: "缺少 OpenSSH", calls: "s"},
		{name: "unreadable server", stat: os.ErrPermission, want: "无法读取", calls: "s"},
		{name: "cannot bind", bind: os.ErrPermission, want: "限制普通程序", calls: "segb", euid: 501},
		{name: "other bind error", bind: busy, want: "无法使用", calls: "segb", euid: 501},
		{name: "installer guard present", euid: 501, guard: true, want: "检查通过", wantReady: true, calls: "segc"},
		{name: "root only checks config", want: "检查通过", wantReady: true, calls: "sec"},
		{name: "ordinary user can bind", euid: 501, want: "检查通过", wantReady: true, calls: "segbc"},
		{name: "interrupted", cancel: true, config: bad, want: "中断或超时", calls: "sec"},
		{name: "missing hostkeys", config: bad, log: "no hostkeys available", want: "主机密钥", calls: "sec"},
		{name: "no output from failed probe", config: bad, want: "配置未通过", calls: "sec"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls strings.Builder
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			st := stoppedCheck{
				stat:     func() error { calls.WriteByte('s'); return tc.stat },
				euid:     func() int { calls.WriteByte('e'); return tc.euid },
				hasGuard: func() bool { calls.WriteByte('g'); return tc.guard },
				bind:     func() error { calls.WriteByte('b'); return tc.bind },
				checkConfig: func(ctx context.Context) (string, error) {
					calls.WriteByte('c')
					if _, ok := ctx.Deadline(); !ok {
						t.Fatal("configuration probe has no deadline")
					}
					return tc.log, tc.config
				},
			}.run(ctx)
			if st.Ready != tc.wantReady || !strings.Contains(st.Message, tc.want) || calls.String() != tc.calls {
				t.Fatalf("check = %+v, calls = %q, want %q and calls %q", st, calls.String(), tc.want, tc.calls)
			}
			if tc.config == bad && !tc.cancel && tc.log == "" && !strings.Contains(st.Detail, bad.Error()) {
				t.Fatal("fallback diagnostic lost cause")
			}
		})
	}
}
