package issuer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// refTime is a fixed clock reference so expiry tests do not depend on the wall
// clock. Grants are stored at second precision, so test times are whole seconds
// except where a test exercises truncation.
var refTime = time.Unix(1_700_000_000, 0).UTC()

func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// newStore opens a grant store on its own temp-file database so tests never
// share state.
func newStore(t testing.TB, now func() time.Time) *GrantStore {
	t.Helper()

	s, err := OpenGrantStore(filepath.Join(t.TempDir(), "grants.db"), WithClock(now))
	if err != nil {
		t.Fatalf("open grant store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	return s
}

// sampleGrant returns a valid grant with every field populated.
func sampleGrant() Grant {
	return Grant{
		Subject:    "user-123",
		DatasetID:  "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001",
		DACSource:  "https://ddbj.nig.ac.jp/dac",
		Asserted:   refTime.Add(-24 * time.Hour),
		Expires:    timePtr(refTime.Add(24 * time.Hour)),
		Conditions: json.RawMessage(`[[{"type":"AffiliationAndRole","value":"faculty@example.org"}]]`),
	}
}

// sameGrant compares grants field by field, treating times by instant and
// conditions by bytes.
func sameGrant(a, b Grant) bool {
	if a.Subject != b.Subject || a.DatasetID != b.DatasetID || a.DACSource != b.DACSource {
		return false
	}
	if !a.Asserted.Equal(b.Asserted) {
		return false
	}
	if (a.Expires == nil) != (b.Expires == nil) {
		return false
	}
	if a.Expires != nil && !a.Expires.Equal(*b.Expires) {
		return false
	}

	return bytes.Equal(a.Conditions, b.Conditions)
}

func TestPutGetRoundTrip(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	want := sampleGrant()

	if err := s.Put(context.Background(), want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(context.Background(), want.Subject, want.DatasetID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !sameGrant(got, want) {
		t.Errorf("round-trip mismatch:\ngot  %+v\nwant %+v", got, want)
	}
}

func TestPutGetRoundTripMinimalGrant(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	want := sampleGrant()
	want.Expires = nil
	want.Conditions = nil

	if err := s.Put(context.Background(), want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(context.Background(), want.Subject, want.DatasetID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Expires != nil {
		t.Errorf("Expires = %v, want nil", got.Expires)
	}
	if got.Conditions != nil {
		t.Errorf("Conditions = %q, want nil", got.Conditions)
	}
	if !sameGrant(got, want) {
		t.Errorf("round-trip mismatch:\ngot  %+v\nwant %+v", got, want)
	}
}

func TestPutTruncatesToSecondPrecision(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	g := sampleGrant()
	g.Asserted = refTime.Add(300 * time.Millisecond)
	g.Expires = timePtr(refTime.Add(time.Hour + 700*time.Millisecond))

	if err := s.Put(context.Background(), g); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(context.Background(), g.Subject, g.DatasetID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Asserted.Equal(refTime) {
		t.Errorf("Asserted = %v, want %v", got.Asserted, refTime)
	}
	if !got.Expires.Equal(refTime.Add(time.Hour)) {
		t.Errorf("Expires = %v, want %v", got.Expires, refTime.Add(time.Hour))
	}
}

func TestPutOverwritesExistingGrant(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	first := sampleGrant()
	if err := s.Put(context.Background(), first); err != nil {
		t.Fatalf("Put: %v", err)
	}

	updated := first
	updated.DACSource = "https://dac.example.org/other"
	updated.Asserted = refTime.Add(-time.Hour)
	updated.Expires = nil
	updated.Conditions = nil
	if err := s.Put(context.Background(), updated); err != nil {
		t.Fatalf("Put update: %v", err)
	}

	got, err := s.Get(context.Background(), first.Subject, first.DatasetID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !sameGrant(got, updated) {
		t.Errorf("grant after upsert:\ngot  %+v\nwant %+v", got, updated)
	}
	all, err := s.ListBySubject(context.Background(), first.Subject)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("got %d grants after upsert, want 1", len(all))
	}
}

func TestPutRejectsInvalidGrant(t *testing.T) {
	mutations := map[string]func(*Grant){
		"empty subject":        func(g *Grant) { g.Subject = "" },
		"empty dataset_id":     func(g *Grant) { g.DatasetID = "" },
		"empty dac_source":     func(g *Grant) { g.DACSource = "" },
		"zero asserted":        func(g *Grant) { g.Asserted = time.Time{} },
		"malformed conditions": func(g *Grant) { g.Conditions = json.RawMessage(`[[{"type":`) },
		"empty conditions":     func(g *Grant) { g.Conditions = json.RawMessage{} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := newStore(t, fixedClock(refTime))
			g := sampleGrant()
			mutate(&g)

			if err := s.Put(context.Background(), g); !errors.Is(err, ErrInvalidGrant) {
				t.Errorf("Put error = %v, want ErrInvalidGrant", err)
			}
			if got, err := s.ListBySubject(context.Background(), g.Subject); err != nil || len(got) != 0 {
				t.Errorf("store not empty after rejected Put: grants %+v, err %v", got, err)
			}
		})
	}
}

func TestGetMissingGrant(t *testing.T) {
	s := newStore(t, fixedClock(refTime))

	if _, err := s.Get(context.Background(), "nobody", "no-dataset"); !errors.Is(err, ErrGrantNotFound) {
		t.Errorf("Get error = %v, want ErrGrantNotFound", err)
	}
}

func TestDeleteRemovesGrant(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	g := sampleGrant()
	if err := s.Put(context.Background(), g); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := s.Delete(context.Background(), g.Subject, g.DatasetID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(context.Background(), g.Subject, g.DatasetID); !errors.Is(err, ErrGrantNotFound) {
		t.Errorf("Get after delete error = %v, want ErrGrantNotFound", err)
	}
	if err := s.Delete(context.Background(), g.Subject, g.DatasetID); !errors.Is(err, ErrGrantNotFound) {
		t.Errorf("second Delete error = %v, want ErrGrantNotFound", err)
	}
}

func TestListBySubjectOrdersByDatasetAndIsolatesSubjects(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	for _, id := range []string{"jga-dataset/JGAD3", "jga-dataset/JGAD1", "jga-dataset/JGAD2"} {
		g := sampleGrant()
		g.DatasetID = id
		if err := s.Put(context.Background(), g); err != nil {
			t.Fatalf("Put %s: %v", id, err)
		}
	}
	other := sampleGrant()
	other.Subject = "someone-else"
	if err := s.Put(context.Background(), other); err != nil {
		t.Fatalf("Put other subject: %v", err)
	}

	got, err := s.ListBySubject(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	want := []string{"jga-dataset/JGAD1", "jga-dataset/JGAD2", "jga-dataset/JGAD3"}
	if len(got) != len(want) {
		t.Fatalf("got %d grants, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].DatasetID != id {
			t.Errorf("grant[%d].DatasetID = %q, want %q", i, got[i].DatasetID, id)
		}
	}
}

func TestActiveBySubjectExpiryBoundary(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	expiries := map[string]*time.Time{
		"at-now":      timePtr(refTime),
		"just-after":  timePtr(refTime.Add(time.Second)),
		"just-before": timePtr(refTime.Add(-time.Second)),
		"never":       nil,
	}
	for id, exp := range expiries {
		g := sampleGrant()
		g.DatasetID = id
		g.Expires = exp
		if err := s.Put(context.Background(), g); err != nil {
			t.Fatalf("Put %s: %v", id, err)
		}
	}

	got, err := s.ActiveBySubject(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("ActiveBySubject: %v", err)
	}
	active := map[string]bool{}
	for _, g := range got {
		active[g.DatasetID] = true
	}
	want := map[string]bool{"at-now": false, "just-after": true, "just-before": false, "never": true}
	for id, wantActive := range want {
		if active[id] != wantActive {
			t.Errorf("dataset %q active = %v, want %v", id, active[id], wantActive)
		}
	}
}

func TestActiveBySubjectWithSubSecondClock(t *testing.T) {
	s := newStore(t, fixedClock(refTime.Add(500*time.Millisecond)))
	for id, exp := range map[string]time.Time{
		"at-now-floor": refTime,
		"next-second":  refTime.Add(time.Second),
	} {
		g := sampleGrant()
		g.DatasetID = id
		g.Expires = timePtr(exp)
		if err := s.Put(context.Background(), g); err != nil {
			t.Fatalf("Put %s: %v", id, err)
		}
	}

	got, err := s.ActiveBySubject(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("ActiveBySubject: %v", err)
	}
	if len(got) != 1 || got[0].DatasetID != "next-second" {
		t.Errorf("active grants = %+v, want only next-second", got)
	}
}

func TestSeedStoresAllGrants(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	a := sampleGrant()
	b := sampleGrant()
	b.DatasetID = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000002"
	c := sampleGrant()
	c.Subject = "user-456"

	if err := s.Seed(context.Background(), []Grant{a, b, c}); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	for _, want := range []Grant{a, b, c} {
		got, err := s.Get(context.Background(), want.Subject, want.DatasetID)
		if err != nil {
			t.Fatalf("Get %s/%s: %v", want.Subject, want.DatasetID, err)
		}
		if !sameGrant(got, want) {
			t.Errorf("seeded grant mismatch:\ngot  %+v\nwant %+v", got, want)
		}
	}
}

func TestSeedLastDuplicateWins(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	first := sampleGrant()
	second := first
	second.DACSource = "https://dac.example.org/other"

	if err := s.Seed(context.Background(), []Grant{first, second}); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	got, err := s.Get(context.Background(), first.Subject, first.DatasetID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !sameGrant(got, second) {
		t.Errorf("grant after duplicate seed:\ngot  %+v\nwant %+v", got, second)
	}
}

func TestSeedRejectsInvalidGrantAndStoresNothing(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	valid := sampleGrant()
	invalid := sampleGrant()
	invalid.Subject = ""

	if err := s.Seed(context.Background(), []Grant{valid, invalid}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("Seed error = %v, want ErrInvalidGrant", err)
	}
	if _, err := s.Get(context.Background(), valid.Subject, valid.DatasetID); !errors.Is(err, ErrGrantNotFound) {
		t.Errorf("valid grant stored despite rejected seed: err = %v", err)
	}
}

func TestOpenGrantStoreFailsOnMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "grants.db")

	s, err := OpenGrantStore(path)
	if err == nil {
		_ = s.Close()
		t.Fatal("OpenGrantStore succeeded, want error for missing parent directory")
	}
}

func TestOperationsFailAfterClose(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	g := sampleGrant()
	if err := s.Put(context.Background(), g); err == nil {
		t.Error("Put on closed store succeeded, want error")
	}
	if _, err := s.Get(context.Background(), g.Subject, g.DatasetID); err == nil {
		t.Error("Get on closed store succeeded, want error")
	}
	if _, err := s.ActiveBySubject(context.Background(), g.Subject); err == nil {
		t.Error("ActiveBySubject on closed store succeeded, want error")
	}
}

func TestOperationsFailOnCanceledContext(t *testing.T) {
	s := newStore(t, fixedClock(refTime))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Put(ctx, sampleGrant()); err == nil {
		t.Error("Put with canceled context succeeded, want error")
	}
}
