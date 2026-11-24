//go:build darwin || linux

package localssh

import (
	"errors"
	"os/user"
	"path/filepath"
	"slices"
	"testing"
)

func TestLoginOwnerResolvesOnlyTheApprovingAccountAndItsGroups(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".peertty-session-fixture")
	lookupErr, groupsErr := errors.New("fixture lookup failure"), errors.New("fixture group lookup failure")
	for _, tt := range []struct {
		name, invoking, uid, gid, username, sessionDir string
		groups                                         []string
		lookup, groupErr                               error
		euid                                           int
		ok, cred                                       bool
		groupCalls                                     int
	}{
		{name: "regular account approvals do not read privileged metadata", euid: 501, uid: "501", gid: "20", username: "robot", ok: true},
		{name: "administrator missing local approver"},
		{name: "administrator cannot be the approver", invoking: "0"},
		{name: "approver disappeared", invoking: "501", lookup: lookupErr},
		{name: "record resolves to administrator", invoking: "501", uid: "0", username: "root"},
		{name: "invalid account", invoking: "501", uid: "501", username: "robot operator"},
		{name: "session path must be canonical", invoking: "501", uid: "501", username: "robot", sessionDir: home + "/./.peertty-session-fixture"},
		{name: "session path must be under home", invoking: "501", uid: "501", username: "robot", sessionDir: filepath.Join(home, "nested", ".peertty-session-fixture")},
		{name: "session path must be a scoped directory", invoking: "501", uid: "501", username: "robot", sessionDir: filepath.Join(home, "another-directory")},
		{name: "invalid numeric ID", invoking: "501", uid: "invalid", gid: "20", username: "robot"},
		{name: "invalid primary group ID", invoking: "501", uid: "501", gid: "invalid", username: "robot"},
		{name: "group lookup unavailable", invoking: "501", uid: "501", gid: "20", username: "robot", groupErr: groupsErr, groupCalls: 1},
		{name: "invalid supplemental group", invoking: "501", uid: "501", gid: "20", username: "robot", groups: []string{"invalid"}, groupCalls: 1},
		{name: "no supplemental groups", invoking: "501", uid: "501", gid: "20", username: "robot", groupCalls: 1, ok: true, cred: true},
		{name: "credentials inherit only approver groups", invoking: "501", uid: "501", gid: "20", username: "robot", groups: []string{"20", "63"}, groupCalls: 1, ok: true, cred: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sessionDir := dir
			if tt.sessionDir != "" {
				sessionDir = tt.sessionDir
			}
			target := &user.User{Uid: tt.uid, Gid: tt.gid, Username: tt.username, HomeDir: home}
			groupCalls := 0
			acct, cred, err := loginOwnerWith(sessionDir, tt.euid, func() string {
				if tt.euid != 0 {
					t.Fatal("normal user should not read privileged metadata")
				}
				return tt.invoking
			}, func() (*user.User, error) {
				if tt.euid != 0 {
					return target, nil
				}
				return &user.User{Uid: "0", Username: "root"}, nil
			}, func(uid string) (*user.User, error) {
				if tt.euid != 0 || uid != "501" {
					t.Fatalf("unexpected approver lookup: %q", uid)
				}
				return target, tt.lookup
			}, func(account *user.User) ([]string, error) {
				groupCalls++
				if account != target {
					t.Fatal("group lookup attempted for another account")
				}
				return tt.groups, tt.groupErr
			})
			if groupCalls != tt.groupCalls {
				t.Fatalf("group calls=%d want %d", groupCalls, tt.groupCalls)
			}
			if !tt.ok {
				if acct != nil || cred != nil || err == nil ||
					tt.lookup != nil && !errors.Is(err, tt.lookup) ||
					tt.groupErr != nil && !errors.Is(err, tt.groupErr) {
					t.Fatalf("invalid owner exposed credentials: %v / %v / %v", acct, cred, err)
				}
				return
			}
			if err != nil || acct != target || (cred != nil) != tt.cred {
				t.Fatalf("owner resolution: %v / %v / %v", acct, cred, err)
			}
			if cred != nil {
				var wantGroups []uint32
				if len(tt.groups) > 0 {
					wantGroups = []uint32{20, 63}
				}
				if cred.Uid != 501 || cred.Gid != 20 || !slices.Equal(cred.Groups, wantGroups) {
					t.Fatalf("credential mismatch: %+v", cred)
				}
			}
		})
	}
}
