package console

import (
	"io"
	"os"
	"strings"
)

// The receipt panel hands this exact input file to OpenSSH on approval. Read
// only available menu input, stopping at the newline and never leaving a
// background reader competing with SSH for the first password or command.
type receiptKeys struct {
	partial []byte
}

func (k *receiptKeys) readAvailable(in *os.File, ready func() (bool, error)) (string, bool, error) {
	var b [1]byte
	for range 256 {
		if ok, err := ready(); !ok || err != nil {
			return "", false, err
		}
		n, err := in.Read(b[:])
		if err != nil {
			return "", false, err
		}
		if n == 0 {
			return "", false, io.EOF
		}
		if b[0] == '\n' {
			value := strings.TrimSpace(string(k.partial))
			if len(k.partial) > 16 {
				value = "?"
			}
			k.partial = k.partial[:0]
			return value, true, nil
		}
		// None of the panel commands needs more than 16 bytes.
		if len(k.partial) < 17 {
			k.partial = append(k.partial, b[0])
		}
	}
	return "", false, nil
}
