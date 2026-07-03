package encryption_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"pgregory.net/rapid"

	"github.com/ddbj/humandbs-drs/internal/encryption"
)

// AtRest must satisfy Provider; a signature drift on either side is a build error.
var _ encryption.Provider = (*encryption.AtRest)(nil)

const tagLen = 16 // GCM tag bytes appended to every chunk

// headerLen mirrors the fixed envelope header: magic(4) + version(1) +
// chunk size(4) + nonce prefix(7).
const headerLen = 16

// mustAtRest builds a provider or fails the test. It takes rapid.TB so both
// *testing.T and *rapid.T can call it.
func mustAtRest(tb rapid.TB, key []byte, chunkSize int) *encryption.AtRest {
	tb.Helper()
	a, err := encryption.NewAtRest(key, chunkSize)
	if err != nil {
		tb.Fatalf("NewAtRest: %v", err)
	}

	return a
}

// encryptBytes seals plain into an envelope or fails the test.
func encryptBytes(tb rapid.TB, a *encryption.AtRest, plain []byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	if err := a.Encrypt(&buf, bytes.NewReader(plain)); err != nil {
		tb.Fatalf("Encrypt: %v", err)
	}

	return buf.Bytes()
}

// drawKey draws a 32-byte key.
func drawKey(rt *rapid.T, label string) []byte {
	return rapid.SliceOfN(rapid.Byte(), encryption.KeySize, encryption.KeySize).Draw(rt, label)
}

// drawPlain draws a plaintext of zero to a few chunks for the given chunk size,
// biased so chunk-boundary lengths (k*chunkSize ± 1) are drawn often.
func drawPlain(rt *rapid.T, chunkSize int) []byte {
	boundaries := []int{
		0, 1,
		chunkSize - 1, chunkSize, chunkSize + 1,
		2*chunkSize - 1, 2 * chunkSize, 2*chunkSize + 1,
	}
	var sizes []int
	for _, s := range boundaries {
		if s >= 0 {
			sizes = append(sizes, s)
		}
	}
	size := rapid.OneOf(
		rapid.SampledFrom(sizes),
		rapid.IntRange(0, 3*chunkSize+2),
	).Draw(rt, "size")

	return rapid.SliceOfN(rapid.Byte(), size, size).Draw(rt, "plain")
}

// expectedStoredSize is the envelope size the format defines: the header plus
// one tag per chunk plus the plaintext, where an empty plaintext still has one
// (empty) chunk and a multiple-of-chunkSize plaintext ends in a full chunk.
func expectedStoredSize(plainLen, chunkSize int) int64 {
	chunks := (plainLen + chunkSize - 1) / chunkSize
	if plainLen == 0 {
		chunks = 1
	}

	return int64(headerLen + chunks*tagLen + plainLen)
}

// TestAtRestRoundTrip pins the core contract: Encrypt writes an envelope of
// exactly the size the format defines, and Reader yields back the plaintext and
// its size.
func TestAtRestRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		chunkSize := rapid.IntRange(1, 257).Draw(rt, "chunkSize")
		a := mustAtRest(rt, drawKey(rt, "key"), chunkSize)
		plain := drawPlain(rt, chunkSize)

		stored := encryptBytes(rt, a, plain)
		if got, want := int64(len(stored)), expectedStoredSize(len(plain), chunkSize); got != want {
			rt.Fatalf("stored size = %d, want %d (plain %d, chunk %d)", got, want, len(plain), chunkSize)
		}

		r, size, err := a.Reader(bytes.NewReader(stored), int64(len(stored)))
		if err != nil {
			rt.Fatalf("Reader: %v", err)
		}
		if size != int64(len(plain)) {
			rt.Fatalf("plaintext size = %d, want %d", size, len(plain))
		}
		got, err := io.ReadAll(r)
		if err != nil {
			rt.Fatalf("ReadAll: %v", err)
		}
		if !bytes.Equal(got, plain) {
			rt.Fatalf("decrypted %d bytes differ from plaintext", len(got))
		}
	})
}

// TestAtRestRangeReadMatchesPlaintext checks that seeking to any plaintext
// offset and reading any length yields the same bytes as slicing the plaintext,
// across several ranges on one reader (so the chunk cache and re-seeks are
// exercised).
func TestAtRestRangeReadMatchesPlaintext(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		chunkSize := rapid.IntRange(1, 129).Draw(rt, "chunkSize")
		a := mustAtRest(rt, drawKey(rt, "key"), chunkSize)
		plain := drawPlain(rt, chunkSize)
		stored := encryptBytes(rt, a, plain)

		r, _, err := a.Reader(bytes.NewReader(stored), int64(len(stored)))
		if err != nil {
			rt.Fatalf("Reader: %v", err)
		}

		ranges := rapid.IntRange(1, 5).Draw(rt, "ranges")
		for i := 0; i < ranges; i++ {
			offset := rapid.IntRange(0, len(plain)).Draw(rt, "offset")
			length := rapid.IntRange(0, len(plain)-offset).Draw(rt, "length")

			if _, err := r.Seek(int64(offset), io.SeekStart); err != nil {
				rt.Fatalf("Seek(%d): %v", offset, err)
			}
			got := make([]byte, length)
			if _, err := io.ReadFull(r, got); err != nil {
				rt.Fatalf("ReadFull(%d bytes at %d): %v", length, offset, err)
			}
			if !bytes.Equal(got, plain[offset:offset+length]) {
				rt.Fatalf("range [%d,%d) differs from plaintext", offset, offset+length)
			}
		}
	})
}

// TestAtRestReadAtEndIsEOF pins the end-of-stream behavior: reading at or past
// the plaintext size answers EOF, including on an empty object.
func TestAtRestReadAtEndIsEOF(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		chunkSize := rapid.IntRange(1, 65).Draw(rt, "chunkSize")
		a := mustAtRest(rt, drawKey(rt, "key"), chunkSize)
		plain := drawPlain(rt, chunkSize)
		stored := encryptBytes(rt, a, plain)

		r, size, err := a.Reader(bytes.NewReader(stored), int64(len(stored)))
		if err != nil {
			rt.Fatalf("Reader: %v", err)
		}
		past := rapid.Int64Range(size, size+3).Draw(rt, "pos")
		if _, err := r.Seek(past, io.SeekStart); err != nil {
			rt.Fatalf("Seek(%d): %v", past, err)
		}
		if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			rt.Fatalf("Read past end = (%d, %v), want (0, EOF)", n, err)
		}
	})
}

// TestAtRestDefaultChunkSize sanity-checks a multi-chunk round-trip at the
// production chunk size.
func TestAtRestDefaultChunkSize(t *testing.T) {
	key := bytes.Repeat([]byte{7}, encryption.KeySize)
	a := mustAtRest(t, key, encryption.DefaultChunkSize)

	plain := make([]byte, encryption.DefaultChunkSize*3+11)
	for i := range plain {
		plain[i] = byte(i * 31)
	}
	stored := encryptBytes(t, a, plain)

	r, size, err := a.Reader(bytes.NewReader(stored), int64(len(stored)))
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	if size != int64(len(plain)) {
		t.Fatalf("plaintext size = %d, want %d", size, len(plain))
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted bytes differ from plaintext")
	}
}
