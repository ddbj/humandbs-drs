package encryption_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"pgregory.net/rapid"

	"github.com/ddbj/humandbs-drs/internal/encryption"
)

// readWhole opens stored with a and reads the plaintext to the end, returning
// the first error from Reader or the read. Corruption tests only require that
// one of the two steps rejects the envelope.
func readWhole(a *encryption.AtRest, stored []byte) error {
	r, _, err := a.Reader(bytes.NewReader(stored), int64(len(stored)))
	if err != nil {
		return err
	}
	_, err = io.ReadAll(r)

	return err
}

// isEnvelopeOrDecryptError reports whether err is one of the two rejection
// paths a corrupted envelope may take: malformed structure or failed
// authentication.
func isEnvelopeOrDecryptError(err error) bool {
	return errors.Is(err, encryption.ErrInvalidEnvelope) || errors.Is(err, encryption.ErrDecrypt)
}

// TestAtRestWrongKeyFails checks that an envelope sealed under one key is
// rejected under another — including an empty plaintext, whose single empty
// chunk must still authenticate before EOF.
func TestAtRestWrongKeyFails(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		chunkSize := rapid.IntRange(1, 129).Draw(rt, "chunkSize")
		key := drawKey(rt, "key")
		other := drawKey(rt, "other")
		if bytes.Equal(key, other) {
			other[0] ^= 0xff
		}
		plain := drawPlain(rt, chunkSize)

		stored := encryptBytes(rt, mustAtRest(rt, key, chunkSize), plain)
		err := readWhole(mustAtRest(rt, other, chunkSize), stored)
		if !errors.Is(err, encryption.ErrDecrypt) {
			rt.Fatalf("read with wrong key = %v, want ErrDecrypt", err)
		}
	})
}

// TestAtRestTamperedByteFails flips one byte anywhere in the envelope and
// requires the read to fail: header corruption as a malformed envelope, body
// corruption as failed authentication.
func TestAtRestTamperedByteFails(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		chunkSize := rapid.IntRange(1, 129).Draw(rt, "chunkSize")
		a := mustAtRest(rt, drawKey(rt, "key"), chunkSize)
		plain := drawPlain(rt, chunkSize)
		stored := encryptBytes(rt, a, plain)

		pos := rapid.IntRange(0, len(stored)-1).Draw(rt, "pos")
		flip := byte(rapid.IntRange(1, 255).Draw(rt, "flip"))
		stored[pos] ^= flip

		err := readWhole(a, stored)
		if !isEnvelopeOrDecryptError(err) {
			rt.Fatalf("read of envelope with byte %d flipped = %v, want ErrInvalidEnvelope or ErrDecrypt", pos, err)
		}
	})
}

// TestAtRestEmptyObjectHeaderTamperFails pins the case the size arithmetic
// alone cannot catch: on an empty object, flipping a chunk-size byte in the
// header leaves the derived plaintext size (zero) unchanged, so only the
// header's authentication as chunk additional data rejects the envelope.
func TestAtRestEmptyObjectHeaderTamperFails(t *testing.T) {
	key := bytes.Repeat([]byte{5}, encryption.KeySize)
	a := mustAtRest(t, key, 1)
	stored := encryptBytes(t, a, nil)

	stored[6] ^= 0x01 // a chunk-size byte
	if err := readWhole(a, stored); !isEnvelopeOrDecryptError(err) {
		t.Fatalf("read of empty object with tampered header = %v, want ErrInvalidEnvelope or ErrDecrypt", err)
	}
}

// TestAtRestTruncatedFails cuts the envelope anywhere — mid-header, mid-chunk,
// at a tag boundary, or whole chunks — and requires the read to fail.
func TestAtRestTruncatedFails(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		chunkSize := rapid.IntRange(1, 129).Draw(rt, "chunkSize")
		a := mustAtRest(rt, drawKey(rt, "key"), chunkSize)
		plain := drawPlain(rt, chunkSize)
		stored := encryptBytes(rt, a, plain)

		keep := rapid.IntRange(0, len(stored)-1).Draw(rt, "keep")
		err := readWhole(a, stored[:keep])
		if !isEnvelopeOrDecryptError(err) {
			rt.Fatalf("read of envelope truncated to %d of %d bytes = %v, want ErrInvalidEnvelope or ErrDecrypt", keep, len(stored), err)
		}
	})
}

// TestAtRestExtendedFails appends bytes to the envelope — including exactly one
// extra chunk's worth — and requires the read to fail, because the last-chunk
// marker no longer lines up.
func TestAtRestExtendedFails(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		chunkSize := rapid.IntRange(1, 129).Draw(rt, "chunkSize")
		a := mustAtRest(rt, drawKey(rt, "key"), chunkSize)
		plain := drawPlain(rt, chunkSize)
		stored := encryptBytes(rt, a, plain)

		extra := rapid.OneOf(
			rapid.IntRange(1, 40),
			rapid.Just(chunkSize+tagLen), // exactly one full chunk
		).Draw(rt, "extra")
		junk := rapid.SliceOfN(rapid.Byte(), extra, extra).Draw(rt, "junk")

		err := readWhole(a, append(stored, junk...))
		if !isEnvelopeOrDecryptError(err) {
			rt.Fatalf("read of envelope extended by %d bytes = %v, want ErrInvalidEnvelope or ErrDecrypt", extra, err)
		}
	})
}

// TestAtRestSeek pins the Seek contract of the plaintext reader: the three
// whence bases resolve in plaintext coordinates, a negative resulting position
// and an unknown whence are errors, and reading after a relative seek yields
// the plaintext at that position.
func TestAtRestSeek(t *testing.T) {
	key := bytes.Repeat([]byte{3}, encryption.KeySize)
	a := mustAtRest(t, key, 8)
	plain := []byte("0123456789abcdefghij") // 20 bytes, chunks of 8
	stored := encryptBytes(t, a, plain)

	r, size, err := a.Reader(bytes.NewReader(stored), int64(len(stored)))
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	if size != int64(len(plain)) {
		t.Fatalf("size = %d, want %d", size, len(plain))
	}

	if pos, err := r.Seek(-4, io.SeekEnd); err != nil || pos != 16 {
		t.Fatalf("Seek(-4, End) = (%d, %v), want (16, nil)", pos, err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, []byte("ghij")) {
		t.Fatalf("read after Seek(End) = (%q, %v), want (\"ghij\", nil)", got, err)
	}

	if pos, err := r.Seek(2, io.SeekStart); err != nil || pos != 2 {
		t.Fatalf("Seek(2, Start) = (%d, %v), want (2, nil)", pos, err)
	}
	if pos, err := r.Seek(3, io.SeekCurrent); err != nil || pos != 5 {
		t.Fatalf("Seek(3, Current) = (%d, %v), want (5, nil)", pos, err)
	}
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, []byte("5678")) {
		t.Fatalf("read after Seek(Current) = (%q, %v), want (\"5678\", nil)", got, err)
	}

	if _, err := r.Seek(-1, io.SeekStart); err == nil {
		t.Fatal("Seek(-1, Start) succeeded, want error")
	}
	if _, err := r.Seek(0, 42); err == nil {
		t.Fatal("Seek(0, whence=42) succeeded, want error")
	}
}

// TestNewAtRestValidation rejects keys that are not 32 bytes and chunk sizes
// outside 1..16 MiB.
func TestNewAtRestValidation(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := encryption.NewAtRest(make([]byte, n), encryption.DefaultChunkSize); !errors.Is(err, encryption.ErrInvalidKey) {
			t.Errorf("NewAtRest(%d-byte key) = %v, want ErrInvalidKey", n, err)
		}
	}
	key := make([]byte, encryption.KeySize)
	for _, cs := range []int{0, -1, 16<<20 + 1} {
		if _, err := encryption.NewAtRest(key, cs); err == nil {
			t.Errorf("NewAtRest(chunkSize=%d) succeeded, want error", cs)
		}
	}
}

// TestReadKeyFile pins the key-file format: hex of exactly 32 bytes with
// surrounding whitespace allowed.
func TestReadKeyFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		return path
	}

	hex64 := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	key, err := encryption.ReadKeyFile(write("good", hex64+"\n"))
	if err != nil {
		t.Fatalf("ReadKeyFile: %v", err)
	}
	if len(key) != encryption.KeySize || key[0] != 0x00 || key[31] != 0x1f {
		t.Fatalf("ReadKeyFile decoded %x", key)
	}

	for name, content := range map[string]string{
		"short":  hex64[:62],
		"long":   hex64 + "20",
		"nothex": "zz" + hex64[2:],
		"empty":  "",
	} {
		if _, err := encryption.ReadKeyFile(write(name, content)); !errors.Is(err, encryption.ErrInvalidKey) {
			t.Errorf("ReadKeyFile(%s) = %v, want ErrInvalidKey", name, err)
		}
	}

	if _, err := encryption.ReadKeyFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("ReadKeyFile(missing) succeeded, want error")
	}
}
