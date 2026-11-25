package console

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"peertty/internal/active"
)

func TestCookedReadStartsAfterFirstKeyAndWaitsForRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := make(chan struct{})
		edit := &cookedLine{owner: make(chan struct{}, 1), waitForKey: func() error { <-key; return nil }}
		in, writer := io.Pipe()
		defer in.Close()
		defer writer.Close()
		done := make(chan line, 1)
		go func() {
			text, err := edit.read(in)
			done <- line{text, err}
		}()
		synctest.Wait()
		if !edit.tryLock() {
			t.Fatal("idle prompt blocked refresh")
		}
		close(key)
		synctest.Wait()
		edit.unlock()
		synctest.Wait()
		if edit.tryLock() {
			t.Fatal("refresh could erase an unfinished input line")
		}
		if _, err := io.WriteString(writer, "  /help\r\n"); err != nil {
			t.Fatal(err)
		}
		if item := <-done; item.err != nil || item.text != "/help" || !edit.tryLock() {
			t.Fatalf("submitted input did not release the screen: %+v", item)
		}
		edit.unlock()
	})
}

func TestHomeKeepsCookedLineAndReportsGrantClosure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out bytes.Buffer
		input := make(chan line, 1)
		edit := &cookedLine{owner: make(chan struct{}, 1)}
		c := &Console{out: &out, fullScreen: true, lineEdit: edit, pending: input}
		closed := make(chan struct{})
		deadline := time.Now().Add(time.Minute)
		done := make(chan line, 1)
		go func() {
			text, err := c.menuChoiceWith(t.Context(), homePage, func(context.Context, string) (active.State, error) {
				select {
				case <-closed:
					return active.State{}, active.ErrInactive
				default:
				}
				s := active.State{ID: "fixture", Role: "host", Phase: "waiting", Deadline: deadline}
				left := time.Minute
				s.Remaining = &left // Each status RPC returns a fresh snapshot.
				return s, nil
			})
			done <- line{text, err}
		}()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		edit.owner <- struct{}{}
		close(closed)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		edit.unlock()
		input <- line{text: "/help"}
		if got := <-done; got.err != nil || got.text != "/help" {
			t.Fatalf("lost pending input: %+v", got)
		}
		log := out.String()
		beforeSubmit := strings.Split(log, erasePage)
		if len(beforeSubmit) != 3 || !strings.Contains(beforeSubmit[1], "剩余 59s") || !strings.Contains(beforeSubmit[1], "授权已结束。") {
			t.Fatal("only the initial draw and submit may clear the screen; grant closure must be visible between them")
		}
	})
}

func TestHostUpdatesGrantWithoutErasingCookedInput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		var out bytes.Buffer
		input := make(chan line, 1)
		edit := &cookedLine{owner: make(chan struct{}, 1)}
		c := &Console{out: &out, fullScreen: true, lineEdit: edit, pending: input}
		st := active.State{ID: "synthetic", Role: "host", Phase: "ready", Device: "测试设备", Route: "UDP", Deadline: time.Now().Add(time.Minute)}
		var streams int
		status := func(context.Context, string) (active.State, error) {
			s := st
			s.Terminals = streams
			return s, nil
		}
		poll := make(chan time.Time)
		done := make(chan error, 1)
		go func() { done <- c.hostPanel(t.Context(), st, nil, poll, hostPanelServices{status: status}) }()
		synctest.Wait()
		if !strings.Contains(out.String(), "对端设备  测试设备") || !strings.Contains(out.String(), "已连终端  0") {
			t.Fatalf("initial host panel omitted grant details: %q", out.String())
		}
		edit.owner <- struct{}{}
		tick := func() string {
			out.Reset()
			time.Sleep(time.Second)
			poll <- time.Now()
			synctest.Wait()
			return out.String()
		}
		topOnly := func(want string) {
			t.Helper()
			log := tick()
			if !strings.Contains(log, want) || !strings.HasPrefix(log, "\x1b7\x1b[H") || !strings.HasSuffix(log, "\x1b8") ||
				strings.Contains(log, erasePage) || strings.Contains(log, "\x1b[2;r") {
				t.Fatalf("expected a cursor-preserving status update containing %q, got %q", want, log)
			}
		}
		topOnly("剩余 59s")
		streams = 1
		topOnly("已连终端 1  剩余 58s")
		topOnly("已连终端 1  剩余 57s")
		edit.unlock()
		if log := tick(); !strings.Contains(log, "已连终端  1") || !strings.Contains(log, "直连路径  UDP") {
			t.Fatalf("host panel did not catch up after editing: %q", log)
		}
		input <- line{text: "b"}
		if err := <-done; !errors.Is(err, errBack) {
			t.Fatalf("pending return command did not survive refresh: %v", err)
		}
	})
}

func TestHostEndKeepsEditedEntryForNextPrompt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out bytes.Buffer
		input := make(chan line, 1)
		edit := &cookedLine{owner: make(chan struct{}, 1)}
		c := &Console{out: &out, fullScreen: true, lineEdit: edit, pending: input}
		edit.owner <- struct{}{}
		done := make(chan error, 1)
		go func() { done <- c.endHostPrompt(t.Context(), active.State{}, "被控会话已结束。", nil) }()
		synctest.Wait()
		input <- line{text: "/help"}
		edit.unlock()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		beforeClear, _, cleared := strings.Cut(out.String(), erasePage)
		if !cleared || !strings.Contains(beforeClear, "被控会话已结束。") {
			t.Fatal("host closure must be visible before the submitted line releases the screen")
		}
		if got := <-c.pending; got.text != "/help" {
			t.Fatalf("next prompt lost the submitted command: %+v", got)
		}
	})
}
