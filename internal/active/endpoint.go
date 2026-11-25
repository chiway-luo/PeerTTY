package active

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"peertty/internal/identitystate"
)

// serveControl publishes an authenticated loopback endpoint for the holder of
// the profile lease. The caller closes it before releasing that lease.
func serveControl(ctx context.Context, profile string, handle func(*tls.Conn)) (func(), error) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	cfg, err := localTLS(key)
	if err != nil {
		return nil, err
	}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", cfg)
	if err != nil {
		return nil, err
	}
	cred := identitystate.RuntimePath(profile, "control.key")
	if err := identitystate.Replace(cred, key.Seed()); err != nil {
		listener.Close()
		return nil, err
	}
	discovery := profile + ".active"
	if err := publishPort(discovery, listener.Addr().(*net.TCPAddr).Port); err != nil {
		listener.Close()
		os.Remove(cred)
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handle(conn.(*tls.Conn))
		}
	}()
	return func() {
		stop()
		listener.Close()
		<-done
		os.Remove(discovery)
		os.Remove(cred)
	}, nil
}

func publishPort(path string, port int) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".peertty-port-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = fmt.Fprintln(tmp, port)
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
