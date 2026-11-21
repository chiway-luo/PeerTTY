package console

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"peertty/internal/grant"
)

func TestDesktopClipboardRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"wl-copy": `cat > "$PEERTTY_TEST_CLIP"`, "wl-paste": `cat "$PEERTTY_TEST_CLIP"`} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":/bin")
	t.Setenv("WAYLAND_DISPLAY", "fixture")
	t.Setenv("PEERTTY_TEST_CLIP", filepath.Join(dir, "clipboard"))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ticket := grant.Ticket{Claims: grant.Claims{SDP: "fixture"}}
	status, err := copyTicket(ctx, io.Discard, ticket)
	if err != nil || !strings.Contains(status, "已复制") {
		t.Fatal(status, err)
	}
	text, err := ticketInput(ctx, "p")
	if err != nil {
		t.Fatal(err)
	}
	read, err := readTicket(text)
	if err != nil || read.Claims.SDP != "fixture" {
		t.Fatal("wrong clipboard payload", err)
	}
}
