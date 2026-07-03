// Package encryption decides how stored object bytes become the plaintext a
// client downloads. It is orthogonal to where the bytes live (a storage.Backend)
// so any backend can be paired with any provider (architecture.md § "storage
// backend と暗号化"). A Provider sits on the delivery path: it turns a reader
// over an object's stored bytes into a reader over its plaintext, and the
// delivery handler applies the requested byte range to that plaintext. Keeping
// the range-to-ciphertext mapping inside the Provider lets at-rest decryption
// stay invisible to the handler.
package encryption

import "io"

// Provider yields the plaintext of a stored object for delivery.
type Provider interface {
	// Reader returns a reader over the plaintext of one stored object, together
	// with the plaintext size, given a reader over its stored bytes and the
	// stored size. The returned reader seeks in plaintext coordinates so the
	// delivery handler can range-read it. none returns src and storedSize
	// unchanged; at-rest returns a decrypting reader and the size net of its
	// envelope.
	Reader(src io.ReadSeeker, storedSize int64) (io.ReadSeeker, int64, error)
}

// None is the identity provider: bytes are stored in the clear, so the plaintext
// is the stored bytes unchanged.
type None struct{}

// Reader passes src and storedSize through: with no encryption the stored bytes
// already are the plaintext.
func (None) Reader(src io.ReadSeeker, storedSize int64) (io.ReadSeeker, int64, error) {
	return src, storedSize, nil
}
