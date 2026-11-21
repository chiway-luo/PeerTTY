package localssh

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestHostCheckRecognizesLocalSSH(t *testing.T) {
	for _, tc := range []struct {
		banner string
		ready  bool
	}{{"local notice\r\nSSH-2.0-fixture\r\n", true}, {"HTTP/1.1 200 OK\r\n", false}, {strings.Repeat("x", 8200) + "\nSSH-2.0-late\n", false}} {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		go func() {
			if c, err := ln.Accept(); err == nil {
				fmt.Fprint(c, tc.banner)
				c.Close()
			}
		}()
		check := CheckHost(context.Background(), port)
		ln.Close()
		if check.Ready != tc.ready || check.Apply != nil {
			t.Fatalf("ready=%t message=%s", check.Ready, check.Message)
		}
		if closed := CheckHost(context.Background(), port); closed.Ready || closed.Action != "" || !strings.Contains(closed.Message, "没有服务监听") {
			t.Fatalf("closed custom port: %+v", closed)
		}
	}
}
