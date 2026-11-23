//go:build darwin || linux

package identitystate

import (
	"fmt"
	"os"
	"syscall"
)

func checkPermissions(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("PeerTTY 状态须由当前用户持有，且仅允许所有者写入: %s", path)
	}
	return nil
}
