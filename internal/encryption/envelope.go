package encryption

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// The at-rest envelope is the on-disk form of one encrypted object
// (architecture.md § "storage backend と暗号化"): a fixed header followed by
// AES-256-GCM chunks.
//
//	magic "HDRS" (4) | version 0x01 (1) | chunk size uint32 BE (4) | nonce prefix (7)
//	chunk 0 | chunk 1 | ... | final chunk
//
// Each chunk seals up to chunk-size plaintext bytes and carries the 16-byte GCM
// tag. The 12-byte chunk nonce is prefix ‖ chunk counter (uint32 BE) ‖ final-chunk
// flag, so reordering, truncating, or extending the chunk sequence fails
// authentication. The header is every chunk's additional data, so tampering
// with it fails authentication too (the plaintext-size arithmetic alone would
// not catch a chunk-size flip on an empty object). An empty plaintext is one
// empty final chunk; a plaintext that
// is an exact multiple of the chunk size ends in a full final chunk, which makes
// the plaintext size a function of the stored size alone.

const (
	envelopeMagic   = "HDRS"
	envelopeVersion = 0x01

	// headerLen is magic(4) + version(1) + chunk size(4) + nonce prefix(7).
	headerLen      = 16
	noncePrefixLen = 7
	nonceLen       = 12
	tagLen         = 16

	// finalChunkFlag is the last nonce byte of the final chunk; every other
	// chunk carries 0x00 there.
	finalChunkFlag = 0x01

	// maxChunkSize caps the chunk size written by Encrypt and accepted from an
	// envelope header, so a tampered header cannot demand an absurd buffer.
	maxChunkSize = 16 << 20

	// maxChunks is the chunk count a uint32 nonce counter can number.
	maxChunks = int64(math.MaxUint32) + 1
)

// Errors reported by the at-rest provider. Callers match them with errors.Is to
// distinguish a key problem, a malformed envelope, and failed authentication
// from plain IO failures.
var (
	// ErrInvalidKey reports a key that is not KeySize bytes.
	ErrInvalidKey = errors.New("encryption: invalid key")
	// ErrInvalidEnvelope reports stored bytes no well-formed envelope can have:
	// a bad magic, version, or chunk size, or a stored size that does not fit
	// the chunk layout.
	ErrInvalidEnvelope = errors.New("encryption: invalid envelope")
	// ErrDecrypt reports a chunk that failed authentication: the stored bytes
	// were tampered with or sealed under a different key.
	ErrDecrypt = errors.New("encryption: decrypt failed")
)

// header is the parsed envelope header.
type header struct {
	chunkSize int64
	prefix    [noncePrefixLen]byte
}

// encodeHeader lays out the fixed envelope header.
func encodeHeader(chunkSize uint32, prefix [noncePrefixLen]byte) [headerLen]byte {
	var b [headerLen]byte
	copy(b[:4], envelopeMagic)
	b[4] = envelopeVersion
	binary.BigEndian.PutUint32(b[5:9], chunkSize)
	copy(b[9:], prefix[:])

	return b
}

// parseHeader validates and decodes the fixed envelope header.
func parseHeader(b [headerLen]byte) (header, error) {
	if !bytes.Equal(b[:4], []byte(envelopeMagic)) {
		return header{}, fmt.Errorf("%w: bad magic %x", ErrInvalidEnvelope, b[:4])
	}
	if b[4] != envelopeVersion {
		return header{}, fmt.Errorf("%w: unsupported version %d", ErrInvalidEnvelope, b[4])
	}
	chunkSize := binary.BigEndian.Uint32(b[5:9])
	if chunkSize == 0 || chunkSize > maxChunkSize {
		return header{}, fmt.Errorf("%w: chunk size %d out of range 1..%d", ErrInvalidEnvelope, chunkSize, maxChunkSize)
	}

	h := header{chunkSize: int64(chunkSize)}
	copy(h.prefix[:], b[9:])

	return h, nil
}

// plainSizeOf derives the plaintext size and chunk count of an envelope of
// storedSize bytes with the given chunk size. The chunk layout makes this
// unique: every chunk but the final one is full, the final one is tag-only
// exactly when it is the only chunk, and a plaintext that fills its final chunk
// keeps it full rather than adding an empty one. A stored size no well-formed
// envelope can have is ErrInvalidEnvelope.
func plainSizeOf(storedSize, chunkSize int64) (plainSize, numChunks int64, err error) {
	body := storedSize - headerLen
	if body < tagLen {
		return 0, 0, fmt.Errorf("%w: %d stored bytes cannot hold the header and one chunk", ErrInvalidEnvelope, storedSize)
	}

	full := chunkSize + tagLen
	n, rest := body/full, body%full
	switch {
	case rest == 0:
		numChunks = n
	case rest < tagLen:
		return 0, 0, fmt.Errorf("%w: %d trailing bytes are shorter than a chunk tag", ErrInvalidEnvelope, rest)
	case rest == tagLen && n >= 1:
		return 0, 0, fmt.Errorf("%w: empty final chunk after full chunks", ErrInvalidEnvelope)
	default:
		numChunks = n + 1
	}
	if numChunks > maxChunks {
		return 0, 0, fmt.Errorf("%w: %d chunks exceed the nonce counter", ErrInvalidEnvelope, numChunks)
	}

	return body - numChunks*tagLen, numChunks, nil
}

// chunkNonce builds the nonce of chunk counter: the envelope's random prefix,
// the chunk's position, and whether it is the final chunk.
func chunkNonce(prefix [noncePrefixLen]byte, counter uint32, final bool) [nonceLen]byte {
	var n [nonceLen]byte
	copy(n[:], prefix[:])
	binary.BigEndian.PutUint32(n[noncePrefixLen:], counter)
	if final {
		n[nonceLen-1] = finalChunkFlag
	}

	return n
}
