package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"peertty/internal/transport"
)

func serverList(urls []string) string {
	if len(urls) == 0 {
		return "已关闭"
	}
	return strings.Join(urls, ", ")
}

func NetworkCheck(ctx context.Context, out io.Writer, spec string, requireMapping bool) error {
	urls, err := transport.STUNServers(spec)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "网络自检 · STUN", serverList(urls))
	candidates, err := transport.CheckNetwork(ctx, spec)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, candidates)
	switch {
	case candidates.Mapped > 0:
		fmt.Fprintln(out, "已取得 UDP 映射。与对端的路径在批准回执后验证。")
	case len(urls) == 0:
		fmt.Fprintln(out, "当前仅探测接口地址。两端分处私网时，可在连接设置中输入 auto 开启 STUN。")
	default:
		fmt.Fprintln(out, "未取得 UDP 映射。请检查 STUN 地址、DNS 和出站 UDP，或换用所在网络可达的 STUN。")
	}
	if requireMapping && candidates.Mapped == 0 {
		return errors.New("本次自检未取得 STUN 映射")
	}
	return nil
}
