package console

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"testing"

	"peertty/internal/grant"
)

func TestSessionIdentitySuppressesInvalidNamesAndKeys(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	showSessionIdentity(&out, "对端", pub, "bad\nname")
	if !strings.Contains(out.String(), grant.ShortFingerprint(grant.Fingerprint(pub))) || strings.Contains(out.String(), "bad") {
		t.Fatal(out.String())
	}
	out.Reset()
	showSessionIdentity(&out, "对端", nil, "Lab device")
	if out.String() != "对端  Lab device\n" {
		t.Fatal(out.String())
	}
}

func TestMultilineTicketPromptAllowsCancelOrReportsEndOfInput(t *testing.T) {
	for _, tc := range []struct {
		name, suffix, want string
		err                error
	}{
		{"cancel", "Q\nnext\n", "Q", nil},
		{"end of stream", "", "", io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.NewReader(ticketBegin + "\n" + tc.suffix)
			text, err := readEntry(input)
			if text != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("incomplete prompted ticket: %q / %v", text, err)
			}
			if tc.err == nil {
				if next, err := readEntry(input); next != "next" || err != nil {
					t.Fatalf("cancel consumed following entry: %q / %v", next, err)
				}
			}
		})
	}
}

func TestTicketSelectionRejectsMissingDataOrNonFile(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct{ name, selected, want string }{
		{"directory", root, "普通邀请或回执文件"},
		{"missing end", ticketBegin + "\nYQ==\n", "凭证文本不完整"},
		{"empty payload", ticketBegin + "\n" + ticketEnd + "\n", "凭证文本为空"},
		{"unrecognized body", ticketBegin + "\nZml4dHVyZQ==\n" + ticketEnd + "\n", "格式不受支持"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readTicket(tc.selected)
			if err == nil || !strings.Contains(err.Error(), tc.want) || got.Claims.Kind != "" || len(got.Signature) != 0 {
				t.Fatalf("expected %q without a ticket, got %v", tc.want, err)
			}
		})
	}
}

func TestClipboardTicketSelectionRejectsAmbiguousCopies(t *testing.T) {
	for _, copy := range []string{
		ticketEnd + "\n" + ticketBegin + "\nfixture\n" + ticketEnd,
		ticketBegin + "\n" + ticketBegin + "\nfixture\n" + ticketEnd,
		ticketBegin + "\nfixture\n" + ticketEnd + "\n" + ticketEnd,
	} {
		if got, err := pastedValue(copy); got != "" || !errors.Is(err, incompletePaste) {
			t.Fatalf("ambiguous paste returned %q, %v", got, err)
		}
	}
}
