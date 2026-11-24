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

func TestClosedHostChecksScopedPolicyBeforeOfferingSessionLogin(t *testing.T) {
	noKeys := errors.New("no hostkeys available")
	probe := stoppedCheck{
		stat: func() error { return nil }, euid: func() int { return 501 },
		hasGuard: func() bool { return false }, bind: func() error { return nil },
		checkConfig:  func(context.Context) (string, error) { return noKeys.Error(), noKeys },
		checkSession: func(context.Context) error { return nil },
	}
	if st := probe.run(t.Context()); !st.Closed || !st.Ready || !st.ScopedOnly || st.Apply != nil {
		t.Fatalf("scoped preflight: %+v", st)
	}
	probe.checkSession = func(context.Context) error { return errors.New("account policy requires system login") }
	if st := probe.run(t.Context()); st.Ready || st.ScopedOnly {
		t.Fatalf("accepted a failed account policy: %+v", st)
	}
}

func TestScopedSSHFallbackRequiresSuccessfulLocalPreflight(t *testing.T) {
	networkErr := errors.New("fixture bind unavailable")
	checkErr := errors.New("configured authentication unavailable")
	for _, tc := range []struct {
		name, log             string
		euid                  int
		bind, session         error
		wantScoped            bool
		wantBind, wantSession int
	}{
		{name: "sudo prompt permits scoped preflight", log: "sudo: a password is required", euid: 501, wantScoped: true, wantBind: 1, wantSession: 1},
		{name: "privileged account cannot use scoped preflight", log: "no hostkeys available", wantScoped: false},
		{name: "unexpected diagnostic is not a reason to change authentication", log: "invalid system config", euid: 501},
		{name: "failed local bind", log: "no hostkeys available", euid: 501, bind: networkErr, wantBind: 1},
		{name: "policy rejected", log: "sudo: a password is required", euid: 501, session: checkErr, wantBind: 1, wantSession: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bind, session int
			p := stoppedCheck{
				stat:         func() error { return nil },
				euid:         func() int { return tc.euid },
				hasGuard:     func() bool { return true },
				bind:         func() error { bind++; return tc.bind },
				checkConfig:  func(context.Context) (string, error) { return tc.log, checkErr },
				checkSession: func(context.Context) error { session++; return tc.session },
			}
			got := p.run(t.Context())
			if got.ScopedOnly != tc.wantScoped || got.Ready != tc.wantScoped || bind != tc.wantBind || session != tc.wantSession {
				t.Fatalf("ready=%v scoped=%v; bind=%d session=%d", got.Ready, got.ScopedOnly, bind, session)
			}
		})
	}
}

func TestConfigurationAdviceDistinguishesPolicyRefusalFromPasswordPrompt(t *testing.T) {
	for _, log := range []string{"user not in the sudoers", "not allowed to execute sshd"} {
		got := unixConfigProblem(log)
		if got.Ready || got.Apply != nil || !strings.Contains(got.Message, "管理员权限") {
			t.Fatalf("permission refusal produced a privileged action: %+v", got)
		}
	}
	got := unixConfigProblem("sudo: a password is required")
	if got.Ready || (got.Apply != nil) != (os.Geteuid() != 0) {
		t.Fatalf("privilege prompt misclassified: %+v", got)
	}
}
