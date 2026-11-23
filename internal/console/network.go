package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

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

	var (
		candidates transport.Candidates
		candErr    error
		natReport  transport.NATReport
		upnpInfo   string
		hasUPnP    bool
	)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		candidates, candErr = transport.CheckNetwork(ctx, spec)
	}()
	if len(urls) > 0 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			natReport, _ = transport.ProbeNAT(ctx, spec)
		}()
		go func() {
			defer wg.Done()
			upnpInfo, hasUPnP = transport.CheckUPnP(ctx)
		}()
	}
	wg.Wait()
	if candErr != nil {
		return candErr
	}
	fmt.Fprintln(out, candidates)
	mapped := candidates.Mapped > 0
	if len(natReport.Probes) > 0 {
		for _, probe := range natReport.Probes {
			fmt.Fprintln(out, "  STUN", probe)
			if probe.Err == nil && probe.Mapped.IsValid() {
				mapped = true
			}
		}
		if verdict := natReport.Verdict(); verdict != "" {
			fmt.Fprintln(out, "NAT 类型 ·", verdict)
		}
	}
	if len(urls) > 0 {
		if hasUPnP {
			fmt.Fprintln(out, "路由器 UPnP · 已发现", upnpInfo+"（配对时将尝试自动映射 UDP 端口）")
		} else {
			fmt.Fprintln(out, "路由器 UPnP · 未发现（仅使用 STUN / ICE 直连）")
		}
	}
	switch {
	case mapped && natReport.Behavior() == transport.NATPortDependent:
		fmt.Fprintln(out, "已取得 STUN 映射，但端口随目的地变化。如果对端也在严格 NAT 后，直连可能失败。")
	case mapped:
		fmt.Fprintln(out, "已取得 STUN 映射。与对端的路径在批准回执后验证。")
	case len(urls) == 0:
		fmt.Fprintln(out, "当前仅探测接口地址。两端分处私网时，可在连接设置中输入 auto 开启 STUN。")
	default:
		fmt.Fprintln(out, "未取得 STUN 映射。请检查 STUN 地址、DNS 和出站 UDP，或换用所在网络可达的 STUN。")
	}
	if requireMapping && !mapped {
		return errors.New("本次自检未取得 STUN 映射")
	}
	return nil
}
