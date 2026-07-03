package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// KeySize is the AES-256 key length NewAtRest requires.
const KeySize = 32

// DefaultChunkSize is the plaintext bytes per chunk Encrypt seals.
const DefaultChunkSize = 64 * 1024

// AtRest stores objects encrypted and decrypts them on the delivery path
// (requirements.md § 4.6): stored bytes are an at-rest envelope of AES-256-GCM
// chunks, and Reader exposes the plaintext with seek support so delivery can
// range-read it, decrypting and authenticating only the chunks a range touches.
type AtRest struct {
	aead      cipher.AEAD
	chunkSize int64
}

// NewAtRest returns a provider sealing and opening envelopes under the given
// 32-byte key. chunkSize is the plaintext bytes per chunk Encrypt writes —
// DefaultChunkSize unless a caller needs smaller chunks; Reader follows the
// chunk size each envelope header records.
func NewAtRest(key []byte, chunkSize int) (*AtRest, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrInvalidKey, len(key), KeySize)
	}
	if chunkSize <= 0 || chunkSize > maxChunkSize {
		return nil, fmt.Errorf("encryption: chunk size %d out of range 1..%d", chunkSize, maxChunkSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}

	return &AtRest{aead: aead, chunkSize: int64(chunkSize)}, nil
}

// Encrypt writes src to dst as an at-rest envelope: the header with a fresh
// random nonce prefix, then one sealed chunk per chunkSize plaintext bytes. An
// empty src still writes one empty final chunk, so every envelope
// authenticates.
func (a *AtRest) Encrypt(dst io.Writer, src io.Reader) error {
	var prefix [noncePrefixLen]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return fmt.Errorf("encryption: draw nonce prefix: %w", err)
	}
	hdr := encodeHeader(uint32(a.chunkSize), prefix)
	if _, err := dst.Write(hdr[:]); err != nil {
		return fmt.Errorf("encryption: write header: %w", err)
	}

	// One chunk of lookahead decides whether the chunk in hand is the final
	// one, which must be marked in its nonce.
	cur := make([]byte, a.chunkSize)
	next := make([]byte, a.chunkSize)
	sealed := make([]byte, 0, a.chunkSize+tagLen)
	curLen, err := readChunk(src, cur)
	if err != nil {
		return err
	}
	for counter := int64(0); ; counter++ {
		nextLen, err := readChunk(src, next)
		if err != nil {
			return err
		}
		if counter >= maxChunks {
			return fmt.Errorf("encryption: plaintext exceeds %d chunks", maxChunks)
		}

		final := nextLen == 0
		nonce := chunkNonce(prefix, uint32(counter), final)
		sealed = a.aead.Seal(sealed[:0], nonce[:], cur[:curLen], hdr[:])
		if _, err := dst.Write(sealed); err != nil {
			return fmt.Errorf("encryption: write chunk %d: %w", counter, err)
		}
		if final {
			return nil
		}
		cur, next = next, cur
		curLen = nextLen
	}
}

// readChunk fills buf as far as src allows and returns the byte count: len(buf)
// with more possibly following, less when src just ended, zero when src was
// already exhausted.
func readChunk(src io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(src, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return n, nil
	}
	if err != nil {
		return 0, fmt.Errorf("encryption: read plaintext: %w", err)
	}

	return n, nil
}

// Reader parses the envelope header of src and returns a seekable reader over
// the plaintext together with the plaintext size, which the chunk layout
// derives from storedSize alone. A malformed header or impossible stored size
// is ErrInvalidEnvelope here; a chunk failing authentication is ErrDecrypt from
// the reader's Read.
func (a *AtRest) Reader(src io.ReadSeeker, storedSize int64) (io.ReadSeeker, int64, error) {
	if storedSize < headerLen+tagLen {
		return nil, 0, fmt.Errorf("%w: %d stored bytes cannot hold the header and one chunk", ErrInvalidEnvelope, storedSize)
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return nil, 0, fmt.Errorf("encryption: seek to header: %w", err)
	}
	var hb [headerLen]byte
	if _, err := io.ReadFull(src, hb[:]); err != nil {
		return nil, 0, fmt.Errorf("encryption: read header: %w", err)
	}
	hdr, err := parseHeader(hb)
	if err != nil {
		return nil, 0, err
	}
	plainSize, numChunks, err := plainSizeOf(storedSize, hdr.chunkSize)
	if err != nil {
		return nil, 0, err
	}

	return &decryptReader{
		src:       src,
		aead:      a.aead,
		hdr:       hdr,
		rawHdr:    hb,
		plainSize: plainSize,
		numChunks: numChunks,
		bufIdx:    -1,
		buf:       make([]byte, 0, hdr.chunkSize),
		sealed:    make([]byte, hdr.chunkSize+tagLen),
	}, plainSize, nil
}

// decryptReader exposes the plaintext of one envelope as an io.ReadSeeker in
// plaintext coordinates. It caches the most recently opened chunk so sequential
// reads decrypt each chunk once, and Seek only repositions, touching the source
// again on the next Read.
type decryptReader struct {
	src       io.ReadSeeker
	aead      cipher.AEAD
	hdr       header
	rawHdr    [headerLen]byte // the chunks' additional data
	plainSize int64
	numChunks int64
	pos       int64
	bufIdx    int64 // chunk index buf holds; -1 before the first load
	buf       []byte
	sealed    []byte
}

func (d *decryptReader) Read(p []byte) (int, error) {
	if d.pos >= d.plainSize {
		// Authenticate the final chunk before reporting EOF, so reading an
		// empty object whole still rejects a wrong key or tampered bytes.
		if d.bufIdx != d.numChunks-1 {
			if err := d.loadChunk(d.numChunks - 1); err != nil {
				return 0, err
			}
		}

		return 0, io.EOF
	}

	idx := d.pos / d.hdr.chunkSize
	if idx != d.bufIdx {
		if err := d.loadChunk(idx); err != nil {
			return 0, err
		}
	}
	off := d.pos - idx*d.hdr.chunkSize
	n := copy(p, d.buf[off:])
	d.pos += int64(n)

	return n, nil
}

// loadChunk reads, authenticates, and caches chunk idx.
func (d *decryptReader) loadChunk(idx int64) error {
	final := idx == d.numChunks-1
	sealedLen := d.hdr.chunkSize + tagLen
	if final {
		sealedLen = d.plainSize - (d.numChunks-1)*d.hdr.chunkSize + tagLen
	}

	if _, err := d.src.Seek(headerLen+idx*(d.hdr.chunkSize+tagLen), io.SeekStart); err != nil {
		return fmt.Errorf("encryption: seek to chunk %d: %w", idx, err)
	}
	if _, err := io.ReadFull(d.src, d.sealed[:sealedLen]); err != nil {
		return fmt.Errorf("encryption: read chunk %d: %w", idx, err)
	}

	nonce := chunkNonce(d.hdr.prefix, uint32(idx), final)
	plain, err := d.aead.Open(d.buf[:0], nonce[:], d.sealed[:sealedLen], d.rawHdr[:])
	if err != nil {
		d.bufIdx = -1

		return fmt.Errorf("%w: chunk %d: %w", ErrDecrypt, idx, err)
	}
	d.buf, d.bufIdx = plain, idx

	return nil
}

func (d *decryptReader) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = d.pos
	case io.SeekEnd:
		base = d.plainSize
	default:
		return 0, fmt.Errorf("encryption: seek: invalid whence %d", whence)
	}
	pos := base + offset
	if pos < 0 {
		return 0, fmt.Errorf("encryption: seek: negative position %d", pos)
	}
	d.pos = pos

	return pos, nil
}
