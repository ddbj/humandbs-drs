package storage

import (
	"fmt"
	"io"
)

// ReadRange copies the byte range [offset, offset+length) of src, whose total
// size is size bytes, to dst and returns the number of bytes copied. The range is
// clamped to the object: an offset at or past size copies nothing, and a length
// of -1 or one that runs past the end reads to the end. A negative offset is
// rejected with ErrInvalidRange. It is the shared primitive behind range delivery
// for every backend: callers resolve the HTTP range forms (start-end, start-,
// suffix) into a concrete (offset, length) and leave clamping here.
func ReadRange(dst io.Writer, src io.ReadSeeker, size, offset, length int64) (int64, error) {
	if offset < 0 {
		return 0, fmt.Errorf("%w: negative offset %d", ErrInvalidRange, offset)
	}
	if offset >= size {
		return 0, nil
	}

	avail := size - offset
	if length < 0 || length > avail {
		length = avail
	}
	if length == 0 {
		return 0, nil
	}

	if _, err := src.Seek(offset, io.SeekStart); err != nil {
		return 0, fmt.Errorf("storage: seek to %d: %w", offset, err)
	}
	n, err := io.CopyN(dst, src, length)
	if err != nil {
		return n, fmt.Errorf("storage: read %d bytes at %d: %w", length, offset, err)
	}

	return n, nil
}
