package active

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"peertty/internal/grant"
	"time"
)

const Command = "_grant"

func Start(ctx context.Context, opts Options) (State, error) {
	var state State
	exe, err := os.Executable()
	if err != nil {
		return state, err
	}
	// Send bootstrap settings through a private pipe; credentials stay out of argv.
	var input bytes.Buffer
	if err = send(&input, opts); err != nil {
		return state, err
	}
	read, write, err := os.Pipe()
	if err != nil {
		return state, err
	}
	defer read.Close()
	cmd := exec.Command(exe, Command)
	detach(cmd)
	cmd.Stdin, cmd.Stdout = &input, write
	logFile := openWorkerLog(opts.Key)
	if logFile != nil {
		cmd.Stderr = logFile
		defer logFile.Close()
	}
	if err = cmd.Start(); err != nil {
		write.Close()
		return state, err
	}
	write.Close()
	go cmd.Wait()
	ready := make(chan error, 1)
	var result reply
	go func() { ready <- receive(read, &result) }()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	return awaitWorkerStart(ctx, timer.C, ready, &result)
}

// The result is read only after ready delivers, which synchronizes the worker's
// prefetched reply with the caller.
func awaitWorkerStart(ctx context.Context, timeout <-chan time.Time, ready <-chan error, result *reply) (State, error) {
	var state State
	select {
	case <-ctx.Done():
		return state, ctx.Err()
	case <-timeout:
		return state, errors.New("后台授权进程启动超时")
	case err := <-ready:
		if err != nil {
			return state, fmt.Errorf("无法启动后台授权进程: %w", err)
		}
		if result.Error != "" {
			switch result.Error {
			case grant.ErrInUse.Error():
				return state, grant.ErrInUse
			case grant.ErrOfferUsed.Error():
				return state, grant.ErrOfferUsed
			}
			return state, errors.New(result.Error)
		}
		state = result.State
		state.startCountdown()
		return state, nil
	}
}

// Main reports startup errors before the parent returns to its prompt.
func Main(ctx context.Context) error {
	err := Serve(ctx, os.Stdin, os.Stdout)
	if err != nil {
		_ = send(os.Stdout, reply{Error: err.Error()})
	}
	return err
}
