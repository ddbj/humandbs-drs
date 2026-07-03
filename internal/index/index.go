// Package index maintains the DRS server's derived object index: a SQLite table
// mapping each canonical DRS id to where its bytes live, its size, sha-256, the
// dataset it belongs to, and its created time. Size and sha-256 describe the
// plaintext a client receives — the bytes the encryption provider exposes — while
// the stored size counts the bytes at rest, which delivery hands back to the
// provider (architecture.md § "index"). Storage (S3/FS) is the source of truth;
// the index is a cache that Rebuild reconstructs by scanning a storage.Backend,
// so it can be nuked and rebuilt to the same rows (architecture.md § "index",
// requirements.md § "データ整合").
package index

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ddbj/humandbs-drs/internal/encryption"
	"github.com/ddbj/humandbs-drs/internal/storage"

	_ "modernc.org/sqlite" // registers the cgo-free "sqlite" driver
)

// ErrObjectNotFound reports a lookup of a DRS id that the index does not hold.
var ErrObjectNotFound = errors.New("index: object not found")

// schema is the object index. size and sha256 describe the plaintext,
// stored_size the bytes at rest; created_at is unix seconds (the file mtime
// carried through from the scan). It is derived from storage, so durability is
// not required.
const schema = `
CREATE TABLE IF NOT EXISTS objects (
    id          TEXT PRIMARY KEY,
    dataset_url TEXT NOT NULL,
    location    TEXT NOT NULL,
    size        INTEGER NOT NULL,
    stored_size INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    created_at  INTEGER NOT NULL
) STRICT;
`

const selectColumns = `id, dataset_url, location, size, stored_size, sha256, created_at`

const insertSQL = `
INSERT INTO objects (id, dataset_url, location, size, stored_size, sha256, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
`

// Record is one row of the index: a DRS object's canonical id, the dataset it
// belongs to, its backend location, sizes, hex sha-256, and created time. It is
// the material a DrsObject is built from.
type Record struct {
	ID         string
	DatasetURL string
	Location   string
	// Size is the plaintext size the client receives; the DrsObject size.
	Size int64
	// StoredSize is the byte count at rest, which delivery hands to the
	// encryption provider. Under no encryption it equals Size.
	StoredSize int64
	SHA256     string
	CreatedAt  time.Time
}

// Index is the SQLite-backed object index.
type Index struct {
	db *sql.DB
}

// Open opens (creating if absent) the SQLite index at path and ensures its
// schema.
func Open(path string) (*Index, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)",
		path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("index: open db: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("index: create schema: %w", err)
	}

	return &Index{db: db}, nil
}

// Close releases the underlying database.
func (ix *Index) Close() error {
	return ix.db.Close()
}

// Rebuild replaces the index with the objects b currently exposes: it scans b,
// sizes and checksums each object's plaintext through enc, and swaps the whole
// table in one transaction so a reader sees the old rows until the new set
// commits. Because the scan assigns deterministic ids and Rebuild reconciles to
// exactly the current tree, running it again on an unchanged tree yields
// identical rows, and additions or removals are reflected. It returns the number
// of objects indexed and errors if a scan produces two objects with the same id
// (an ambiguous manifest).
func (ix *Index) Rebuild(ctx context.Context, b storage.Backend, enc encryption.Provider) (int, error) {
	var records []Record
	seen := make(map[string]string)

	err := b.Scan(ctx, func(e storage.Entry) error {
		if prev, dup := seen[e.ID]; dup {
			return fmt.Errorf("index: colliding id %q for %q and %q", e.ID, prev, e.Location)
		}
		seen[e.ID] = e.Location

		size, sum, err := plainInfo(ctx, b, enc, e.Location, e.Size)
		if err != nil {
			return err
		}
		records = append(records, Record{
			ID:         e.ID,
			DatasetURL: e.DatasetURL,
			Location:   e.Location,
			Size:       size,
			StoredSize: e.Size,
			SHA256:     sum,
			CreatedAt:  e.ModTime.UTC(),
		})

		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("index: rebuild: %w", err)
	}
	if err := ix.replaceAll(ctx, records); err != nil {
		return 0, err
	}

	return len(records), nil
}

// Get returns the record for id, or ErrObjectNotFound.
func (ix *Index) Get(ctx context.Context, id string) (Record, error) {
	row := ix.db.QueryRowContext(ctx, `SELECT `+selectColumns+` FROM objects WHERE id = ?`, id)

	r, err := scanRecord(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("%w: %q", ErrObjectNotFound, id)
	}
	if err != nil {
		return Record{}, fmt.Errorf("index: get object: %w", err)
	}

	return r, nil
}

// List returns every indexed object ordered by id.
func (ix *Index) List(ctx context.Context) ([]Record, error) {
	rows, err := ix.db.QueryContext(ctx, `SELECT `+selectColumns+` FROM objects ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("index: list objects: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []Record
	for rows.Next() {
		r, err := scanRecord(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("index: list objects: %w", err)
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("index: list objects: %w", err)
	}

	return records, nil
}

// replaceAll swaps the table contents for records in one transaction. File IO
// (the checksums) already happened, so the write lock is held only for the row
// swap.
func (ix *Index) replaceAll(ctx context.Context, records []Record) error {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("index: rebuild: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM objects`); err != nil {
		return fmt.Errorf("index: rebuild: %w", err)
	}
	for _, r := range records {
		if _, err := tx.ExecContext(ctx, insertSQL,
			r.ID, r.DatasetURL, r.Location, r.Size, r.StoredSize, r.SHA256, r.CreatedAt.Unix()); err != nil {
			return fmt.Errorf("index: rebuild: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("index: rebuild: %w", err)
	}

	return nil
}

// plainInfo opens the object at loc through b, exposes its plaintext through
// enc, and returns the plaintext size and hex sha-256. Reading the plaintext
// whole also authenticates every chunk of an encrypted object, so a wrong key
// or corrupted envelope fails the rebuild rather than entering the index.
func plainInfo(ctx context.Context, b storage.Backend, enc encryption.Provider, loc string, storedSize int64) (int64, string, error) {
	rsc, err := b.Open(ctx, loc)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = rsc.Close() }()

	plain, size, err := enc.Reader(rsc, storedSize)
	if err != nil {
		return 0, "", fmt.Errorf("index: plaintext of %q: %w", loc, err)
	}
	h := sha256.New()
	n, err := io.Copy(h, plain)
	if err != nil {
		return 0, "", fmt.Errorf("index: checksum %q: %w", loc, err)
	}
	if n != size {
		return 0, "", fmt.Errorf("index: plaintext of %q is %d bytes, provider sized it %d", loc, n, size)
	}

	return size, hex.EncodeToString(h.Sum(nil)), nil
}

// scanRecord reads one selectColumns row via scan, restoring created_at from unix
// seconds.
func scanRecord(scan func(dest ...any) error) (Record, error) {
	var (
		r         Record
		createdAt int64
	)
	if err := scan(&r.ID, &r.DatasetURL, &r.Location, &r.Size, &r.StoredSize, &r.SHA256, &createdAt); err != nil {
		return Record{}, err
	}
	r.CreatedAt = time.Unix(createdAt, 0).UTC()

	return r, nil
}
