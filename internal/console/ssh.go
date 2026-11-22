package console

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"peertty/internal/localssh"
)

var errNewWindow = errors.New("已转到管理员窗口")

func (t *Console) option(key, label string) {
	if t.terminalUI() {
		t.line(t.view().key(key), label)
		return
	}
	fmt.Fprintf(t.out, "  %s  %s\n", key, label)
}

func (t *Console) hostReady(ctx context.Context) error {
	return t.checkSSH(ctx, true, func() localssh.Check { return localssh.CheckHost(ctx, t.SSHPort) })
}

func (t *Console) checkSSH(ctx context.Context, host bool, inspect func() localssh.Check) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		st := inspect()
		if st.Ready {
			t.notice("32", "✓", st.Message)
		} else {
			t.notice("33", "!", st.Message)
		}
		if st.Detail != "" {
			t.line(st.Detail)
		}
		if st.Ready {
			return nil
		}
		if st.Action != "" {
			t.option("1", st.Action)
		}
		t.option("2", "重新检查")
		if host {
			t.option("3", "修改本机 SSH 端口")
		}
		t.option("0", "返回主菜单")
		choice, err := t.prompt(ctx, "选择 > ")
		if err != nil {
			return err
		}
		switch choice {
		case "0":
			return errBack
		case "1":
			if st.StartAdmin != nil {
				// Only menu settings travel to the new window. No invitation or
				// approval is created or carried across an elevation boundary.
				args := []string{"menu", "-key", t.KeyPath, "-stun", t.STUN, "-ttl", t.TTL.String(), "-ssh-port", strconv.Itoa(t.SSHPort)}
				if err := st.StartAdmin(args); err == nil {
					return errNewWindow
				} else {
					t.notice("33", "!", "未打开管理员窗口 · "+err.Error())
				}
			} else if st.Apply != nil {
				var path string
				if st.PackageExt != "" {
					name, err := t.prompt(ctx, "PeerTTY "+st.PackageExt+" 安装包路径（q 返回） > ")
					if err != nil {
						return err
					}
					if name == "" {
						continue
					}
					if path, err = userPath(name); err != nil {
						t.notice("33", "!", "无法读取安装包路径 · "+err.Error())
						continue
					}
				}
				if err := st.Apply(ctx, t.in, t.pageOut(), path); err != nil {
					t.notice("33", "!", "系统操作未完成 · "+err.Error())
				}
			} else {
				t.notice("33", "!", "请选择屏幕列出的操作。")
			}
		case "2":
		case "3":
			if host {
				port, err := t.selectSSHPort(ctx)
				if err != nil {
					return err
				}
				t.SSHPort = port
			} else {
				t.notice("33", "!", "请选择屏幕列出的操作。")
			}
		default:
			t.notice("33", "!", "请选择屏幕列出的操作。")
		}
	}
}
