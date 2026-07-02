package issuer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // registers the cgo-free "sqlite" driver
)

// schema is the grant table. Timestamps are unix seconds, the resolution of the
// JWT claims they feed; expires NULL means the grant never lapses. The primary
// key makes one grant per (subject, dataset) the invariant that Put upserts
// against (architecture.md § "Issuer 設計").
const schema = `
CREATE TABLE IF NOT EXISTS grants (
    subject    TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    dac_source TEXT NOT NULL,
    asserted   INTEGER NOT NULL,
    expires    INTEGER,
    conditions BLOB,
    PRIMARY KEY (subject, dataset_id)
) STRICT;
`

const upsertSQL = `
INSERT INTO grants (subject, dataset_id, dac_source, asserted, expires, conditions)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (subject, dataset_id) DO UPDATE SET
    dac_source = excluded.dac_source,
    asserted   = excluded.asserted,
    expires    = excluded.expires,
    conditions = excluded.conditions
`

const selectColumns = `subject, dataset_id, dac_source, asserted, expires, conditions`

// GrantStore persists grants in SQLite and answers which of them are active.
// Sub-second precision in Grant timestamps is truncated on store.
type GrantStore struct {
	db  *sql.DB
	now func() time.Time
}

// GrantStoreOption adjusts a GrantStore at construction.
type GrantStoreOption func(*GrantStore)

// WithClock replaces the wall clock that activity checks compare expiry
// against. Tests inject a fixed clock to make expiry deterministic.
func WithClock(now func() time.Time) GrantStoreOption {
	return func(s *GrantStore) {
		s.now = now
	}
}

// OpenGrantStore opens (creating if absent) the SQLite grant database at path
// and ensures its schema.
func OpenGrantStore(path string, opts ...GrantStoreOption) (*GrantStore, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)",
		path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("issuer: open grant db: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("issuer: create grant schema: %w", err)
	}

	s := &GrantStore{db: db, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Close releases the underlying database.
func (s *GrantStore) Close() error {
	return s.db.Close()
}

// Put stores g, replacing any existing grant for the same (subject, dataset):
// re-seeding a grant updates its dac_source, asserted, expires, and conditions.
func (s *GrantStore) Put(ctx context.Context, g Grant) error {
	if err := g.Validate(); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, upsertSQL, upsertArgs(g)...); err != nil {
		return fmt.Errorf("issuer: put grant: %w", err)
	}

	return nil
}

// Seed stores grants as one transaction: either every grant lands or none do.
// All grants are validated before any row is written.
func (s *GrantStore) Seed(ctx context.Context, grants []Grant) error {
	for _, g := range grants {
		if err := g.Validate(); err != nil {
			return err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("issuer: seed grants: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, g := range grants {
		if _, err := tx.ExecContext(ctx, upsertSQL, upsertArgs(g)...); err != nil {
			return fmt.Errorf("issuer: seed grants: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("issuer: seed grants: %w", err)
	}

	return nil
}

// Get returns the grant for (subject, datasetID), or ErrGrantNotFound.
func (s *GrantStore) Get(ctx context.Context, subject, datasetID string) (Grant, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+selectColumns+` FROM grants WHERE subject = ? AND dataset_id = ?`,
		subject, datasetID)

	g, err := scanGrant(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, fmt.Errorf("%w: subject %q, dataset %q", ErrGrantNotFound, subject, datasetID)
	}
	if err != nil {
		return Grant{}, fmt.Errorf("issuer: get grant: %w", err)
	}

	return g, nil
}

// Delete removes the grant for (subject, datasetID). Deleting a grant that does
// not exist reports ErrGrantNotFound so a revocation that hit nothing is visible.
func (s *GrantStore) Delete(ctx context.Context, subject, datasetID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM grants WHERE subject = ? AND dataset_id = ?`, subject, datasetID)
	if err != nil {
		return fmt.Errorf("issuer: delete grant: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("issuer: delete grant: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: subject %q, dataset %q", ErrGrantNotFound, subject, datasetID)
	}

	return nil
}

// ListBySubject returns every grant for subject, expired ones included, ordered
// by dataset_id. It serves administrative inspection; visa issuance uses
// ActiveBySubject.
func (s *GrantStore) ListBySubject(ctx context.Context, subject string) ([]Grant, error) {
	return s.queryGrants(ctx,
		`SELECT `+selectColumns+` FROM grants WHERE subject = ? ORDER BY dataset_id`,
		subject)
}

// ActiveBySubject returns the grants for subject that are active now: those
// that never expire or whose expiry is strictly in the future. A grant whose
// expiry is at or before the current time is excluded, matching how visa
// verification treats `exp`. Ordered by dataset_id.
func (s *GrantStore) ActiveBySubject(ctx context.Context, subject string) ([]Grant, error) {
	return s.queryGrants(ctx,
		`SELECT `+selectColumns+` FROM grants
		 WHERE subject = ? AND (expires IS NULL OR expires > ?) ORDER BY dataset_id`,
		subject, s.now().Unix())
}

func (s *GrantStore) queryGrants(ctx context.Context, query string, args ...any) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("issuer: query grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var grants []Grant
	for rows.Next() {
		g, err := scanGrant(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("issuer: query grants: %w", err)
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("issuer: query grants: %w", err)
	}

	return grants, nil
}

// upsertArgs flattens g into the upsertSQL parameters, mapping a nil Expires to
// NULL and truncating timestamps to unix seconds.
func upsertArgs(g Grant) []any {
	var expires any
	if g.Expires != nil {
		expires = g.Expires.Unix()
	}
	var conditions any
	if g.Conditions != nil {
		conditions = []byte(g.Conditions)
	}

	return []any{g.Subject, g.DatasetID, g.DACSource, g.Asserted.Unix(), expires, conditions}
}

// scanGrant reads one selectColumns row via scan, reversing upsertArgs' mapping.
func scanGrant(scan func(dest ...any) error) (Grant, error) {
	var (
		g        Grant
		asserted int64
		expires  sql.NullInt64
		cond     []byte
	)
	if err := scan(&g.Subject, &g.DatasetID, &g.DACSource, &asserted, &expires, &cond); err != nil {
		return Grant{}, err
	}

	g.Asserted = time.Unix(asserted, 0).UTC()
	if expires.Valid {
		t := time.Unix(expires.Int64, 0).UTC()
		g.Expires = &t
	}
	if cond != nil {
		g.Conditions = json.RawMessage(cond)
	}

	return g, nil
}
