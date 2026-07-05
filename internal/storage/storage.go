// Package storage abstracts where controlled-access object bytes live and turns
// a storage tree into DRS objects. A Backend enumerates the objects it exposes,
// assigning each a canonical, deterministic DRS id, and opens their bytes for
// range reads. The filesystem backend DRS-ifies an existing read-only directory
// in place; a future s3 backend loads SeaweedFS. Both look identical to the DRS
// API (architecture.md § "storage backend と暗号化", § "index").
package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

// Errors reported by the package. Callers match these with errors.Is to
// distinguish a rejected manifest, an out-of-tree location, or a bad range from
// an IO failure.
var (
	// ErrInvalidManifest reports a manifest or dataset that fails validation and
	// was not loaded.
	ErrInvalidManifest = errors.New("storage: invalid manifest")
	// ErrLocationOutsideRoot reports an Open whose location escapes every
	// configured dataset root, so a stale or tampered index cannot read arbitrary
	// files through the backend.
	ErrLocationOutsideRoot = errors.New("storage: location outside dataset roots")
	// ErrInvalidRange reports a range read with a negative offset.
	ErrInvalidRange = errors.New("storage: invalid range")
	// ErrInvalidID reports a caller-supplied DRS id that does not follow the
	// backend's object ID scheme (architecture.md § "object ID scheme").
	ErrInvalidID = errors.New("storage: invalid object id")
)

// Entry is one object discovered by a scan: its canonical DRS id, the dataset it
// belongs to, its backend-specific location, and the size and modification time
// stat reported. Rebuilding the index reads bytes through Backend.Open to add the
// checksum, so Entry itself is stat-only and a scan stays cheap.
type Entry struct {
	// ID is the canonical DRS object id (architecture.md § "object ID scheme").
	ID string
	// DatasetURL is the dataset resource URL the object belongs to, matched
	// verbatim against a visa `value` (architecture.md § "dataset 識別").
	DatasetURL string
	// Location is the backend-specific locator handed back to Open. The filesystem
	// backend uses the absolute file path; s3 will use the object key.
	Location string
	// Size is the object size in bytes.
	Size int64
	// ModTime is the file modification time, used as the DRS created_time so it
	// survives an index rebuild (architecture.md § "index").
	ModTime time.Time
}

// Backend abstracts a storage tree of controlled-access objects.
type Backend interface {
	// Scan enumerates the objects the backend currently exposes, calling visit
	// once per object with its canonical DRS id and stat metadata. A scan assigns
	// the same ids on every run so the index can be rebuilt (architecture.md
	// § "object ID scheme"). Scan stops and returns visit's error if it is non-nil.
	Scan(ctx context.Context, visit func(Entry) error) error
	// Open opens the object bytes at loc for reading, seeking, and closing. The
	// returned reader supports range reads via Seek; delivery streams from it and
	// the index reads it whole to checksum. loc must be one the backend produced.
	Open(ctx context.Context, loc string) (io.ReadSeekCloser, error)
}
