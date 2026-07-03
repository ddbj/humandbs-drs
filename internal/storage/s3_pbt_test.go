package storage

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/ddbj/humandbs-drs/internal/encryption"

	"pgregory.net/rapid"
)

// TestS3RoundTripPBT: any blob uploaded through Put reads back byte-for-byte via
// Open, including the empty object.
func TestS3RoundTripPBT(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		content := rapid.SliceOfN(rapid.Byte(), 0, 4096).Draw(rt, "content")

		fake := newFakeS3()
		b := newS3Backend(fake, s3Bucket, "objects/")
		ctx := context.Background()

		entry, err := b.Put(ctx, urlA, bytes.NewReader(content))
		if err != nil {
			rt.Fatalf("Put: %v", err)
		}
		rsc, err := b.Open(ctx, entry.Location)
		if err != nil {
			rt.Fatalf("Open: %v", err)
		}
		got, err := io.ReadAll(rsc)
		_ = rsc.Close()
		if err != nil {
			rt.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, content) {
			rt.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(content))
		}
	})
}

// TestS3RangeReadPBT: reading any range through the lazy seek reader matches the
// same slice of the original bytes.
func TestS3RangeReadPBT(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		content := rapid.SliceOfN(rapid.Byte(), 1, 2048).Draw(rt, "content")
		size := int64(len(content))
		offset := rapid.Int64Range(0, size).Draw(rt, "offset")
		length := rapid.Int64Range(-1, size).Draw(rt, "length")

		fake := newFakeS3()
		b := newS3Backend(fake, s3Bucket, "")
		ctx := context.Background()

		entry, err := b.Put(ctx, urlA, bytes.NewReader(content))
		if err != nil {
			rt.Fatalf("Put: %v", err)
		}
		rsc, err := b.Open(ctx, entry.Location)
		if err != nil {
			rt.Fatalf("Open: %v", err)
		}
		var buf bytes.Buffer
		n, err := ReadRange(&buf, rsc, size, offset, length)
		_ = rsc.Close()
		if err != nil {
			rt.Fatalf("ReadRange(%d,%d): %v", offset, length, err)
		}

		want := clampRange(content, offset, length)
		if int(n) != len(want) || !bytes.Equal(buf.Bytes(), want) {
			rt.Fatalf("ReadRange(%d,%d) = %d bytes, want %d", offset, length, n, len(want))
		}
	})
}

// clampRange mirrors ReadRange's clamping to derive the expected slice.
func clampRange(content []byte, offset, length int64) []byte {
	size := int64(len(content))
	if offset >= size {
		return nil
	}
	avail := size - offset
	if length < 0 || length > avail {
		length = avail
	}

	return content[offset : offset+length]
}

// TestS3AtRestRangeRead exercises the (s3, at-rest) pairing: an at-rest envelope
// stored in S3 decrypts to the plaintext through the lazy seek reader, whose
// per-chunk seek-then-read is what at-rest delivery relies on.
func TestS3AtRestRangeRead(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		key := rapid.SliceOfN(rapid.Byte(), encryption.KeySize, encryption.KeySize).Draw(rt, "key")
		chunkSize := rapid.IntRange(1, 65).Draw(rt, "chunkSize")
		plaintext := rapid.SliceOfN(rapid.Byte(), 0, 512).Draw(rt, "plaintext")
		size := int64(len(plaintext))
		offset := rapid.Int64Range(0, size).Draw(rt, "offset")
		length := rapid.Int64Range(-1, size).Draw(rt, "length")

		prov, err := encryption.NewAtRest(key, chunkSize)
		if err != nil {
			rt.Fatalf("NewAtRest: %v", err)
		}
		var envelope bytes.Buffer
		if err := prov.Encrypt(&envelope, bytes.NewReader(plaintext)); err != nil {
			rt.Fatalf("Encrypt: %v", err)
		}
		storedSize := int64(envelope.Len())

		fake := newFakeS3()
		b := newS3Backend(fake, s3Bucket, "")
		ctx := context.Background()
		entry, err := b.Put(ctx, urlA, bytes.NewReader(envelope.Bytes()))
		if err != nil {
			rt.Fatalf("Put: %v", err)
		}

		rsc, err := b.Open(ctx, entry.Location)
		if err != nil {
			rt.Fatalf("Open: %v", err)
		}
		defer func() { _ = rsc.Close() }()

		plain, plainSize, err := prov.Reader(rsc, storedSize)
		if err != nil {
			rt.Fatalf("Reader: %v", err)
		}
		if plainSize != size {
			rt.Fatalf("plaintext size = %d, want %d", plainSize, size)
		}

		var buf bytes.Buffer
		if _, err := ReadRange(&buf, plain, plainSize, offset, length); err != nil {
			rt.Fatalf("ReadRange(%d,%d): %v", offset, length, err)
		}
		want := clampRange(plaintext, offset, length)
		if !bytes.Equal(buf.Bytes(), want) {
			rt.Fatalf("decrypted range mismatch at (%d,%d): got %d bytes, want %d", offset, length, buf.Len(), len(want))
		}
	})
}
