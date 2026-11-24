package console

import (
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"peertty/internal/grant"
)

const ticketType = "PEERTTY TICKET"
const ticketBegin = "-----BEGIN " + ticketType + "-----"
const ticketEnd = "-----END " + ticketType + "-----"

// Short PEM lines round-trip through terminals with a canonical input limit.
// Invitations must be readable before the recipient's version is known.
func writeTicketText(out io.Writer, ticket grant.Ticket) error {
	data, err := json.Marshal(ticket)
	if err != nil {
		return err
	}
	if ticket.Claims.Kind != "answer" || !ticket.CompactReply {
		return pem.Encode(out, &pem.Block{Type: ticketType, Bytes: data})
	}
	payload := data
	var compressed bytes.Buffer
	if zw, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression); err == nil {
		if _, wErr := zw.Write(data); wErr == nil && zw.Close() == nil && compressed.Len() < len(data) {
			payload = compressed.Bytes()
		}
	}
	return pem.Encode(out, &pem.Block{Type: ticketType, Bytes: payload})
}

func readEntry(in io.Reader) (string, error) {
	first, err := readLine(in)
	if err != nil {
		return first, err
	}
	if first != ticketBegin {
		// In terminals without bracketed paste (e.g. Windows ConHost), a user
		// may copy a heading prefix on the same line before BEGIN.
		if idx := strings.Index(first, ticketBegin); idx > 0 {
			first = first[idx:]
		} else {
			return first, nil
		}
	}
	var block strings.Builder
	block.WriteString(first)
	full := false
	for {
		line, err := readLine(in)
		if err == oversizePaste {
			full = true
			continue
		}
		if err != nil || strings.EqualFold(line, "q") {
			return line, err
		}
		if !full {
			full = block.Len()+1+len(line) > maxPaste
			if !full {
				block.WriteByte('\n')
				block.WriteString(line)
			}
		}
		if line == ticketEnd {
			if full {
				return "", oversizePaste
			}
			return block.String(), nil
		}
	}
}

// A framed selection may include the adjacent display label. Only one ticket
// is accepted and other lines in the selection never become menu input.
func pastedValue(s string) (string, error) {
	if len(s) > maxPaste {
		return "", oversizePaste
	}
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n"))
	if strings.HasPrefix(s, "{") {
		return s, nil
	}
	before, body, begin := strings.Cut(s, ticketBegin)
	if begin {
		inside, after, end := strings.Cut(body, ticketEnd)
		if !end || strings.Contains(before, ticketEnd) || strings.Contains(inside, ticketBegin) ||
			strings.Contains(after, ticketBegin) || strings.Contains(after, ticketEnd) {
			return "", incompletePaste
		}
		return ticketBegin + "\n" + strings.TrimSpace(inside) + "\n" + ticketEnd, nil
	}
	if strings.ContainsAny(s, "\n\x1b") || strings.Contains(s, ticketEnd) {
		return "", incompletePaste
	}
	return s, nil
}

func isTicketText(s string) bool {
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, ticketBegin+"\n")
}

func validDeviceName(name string) bool {
	return name != "" && len(name) <= 255 && !strings.ContainsFunc(name, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("-_. '’()", r)
	})
}

func showDeviceName(out io.Writer, label, name string) {
	if validDeviceName(name) {
		fmt.Fprintf(out, "%s  %s\n", label, name)
	}
}

func showSessionIdentity(out io.Writer, label string, issuer ed25519.PublicKey, name string) {
	showDeviceName(out, label, name)
	if len(issuer) == ed25519.PublicKeySize {
		fmt.Fprintf(out, "本次会话指纹  %s\n", grant.ShortFingerprint(grant.Fingerprint(issuer)))
	}
}

func decodeTicketPayload(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("凭证文本为空")
	}
	if trimmed[0] == '{' {
		return trimmed, nil
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("凭证文本不完整或格式不受支持")
	}
	defer zr.Close()
	data, err := io.ReadAll(io.LimitReader(zr, grant.MaxTicketSize+1))
	if err != nil {
		return nil, errors.New("凭证文本解压失败")
	}
	if len(data) > grant.MaxTicketSize {
		return nil, errors.New("凭证内容超过大小限制")
	}
	return data, nil
}

func readTicket(s string) (grant.Ticket, error) {
	if strings.HasPrefix(s, ticketBegin+"\n") {
		block, rest := pem.Decode([]byte(s))
		if block == nil || block.Type != ticketType || len(rest) != 0 {
			return grant.Ticket{}, errors.New("凭证文本不完整")
		}
		data, err := decodeTicketPayload(block.Bytes)
		if err != nil {
			return grant.Ticket{}, err
		}
		return grant.Parse(data)
	}
	if strings.HasPrefix(s, "{") {
		return grant.Parse([]byte(s))
	}
	p, err := userPath(s)
	if err != nil {
		return grant.Ticket{}, err
	}
	info, err := os.Stat(p)
	if err != nil {
		return grant.Ticket{}, err
	}
	if !info.Mode().IsRegular() {
		return grant.Ticket{}, errors.New("请选择普通邀请或回执文件")
	}
	return grant.Read(p)
}
