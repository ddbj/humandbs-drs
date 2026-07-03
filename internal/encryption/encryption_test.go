package encryption_test

import (
	"bytes"
	"io"
	"testing"

	"pgregory.net/rapid"

	"github.com/ddbj/humandbs-drs/internal/encryption"
)

// None must satisfy Provider; a signature drift on either side is a build error.
var _ encryption.Provider = encryption.None{}

// TestNoneIsIdentity pins the pass-through contract: None hands back the same
// reader and stored size, and reading through it yields the stored bytes
// verbatim. Delivery relies on this so a plaintext backend needs no decryption.
func TestNoneIsIdentity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		data := rapid.SliceOf(rapid.Byte()).Draw(rt, "data")
		src := bytes.NewReader(data)

		plain, size, err := encryption.None{}.Reader(src, int64(len(data)))
		if err != nil {
			rt.Fatalf("Reader: %v", err)
		}
		if size != int64(len(data)) {
			rt.Errorf("size = %d, want %d", size, len(data))
		}
		if plain != io.ReadSeeker(src) {
			rt.Errorf("Reader returned a different reader, want src unchanged")
		}

		got, err := io.ReadAll(plain)
		if err != nil {
			rt.Fatalf("ReadAll: %v", err)
		}
		if !bytes.Equal(got, data) {
			rt.Errorf("read %x, want %x", got, data)
		}
	})
}
