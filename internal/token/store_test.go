package token

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"
)

var refTime = time.Unix(1_700_000_000, 0).UTC()

const (
	testTTL     = 5 * time.Minute
	testDataset = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001"
)

// storeAt returns a Store pinned to a mutable clock.
func storeAt(t *testing.T, at *time.Time) *Store {
	t.Helper()

	s, err := NewStore(testTTL, WithClock(func() time.Time { return *at }))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	return s
}

func TestNewStoreRequiresPositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute} {
		if _, err := NewStore(ttl); err == nil {
			t.Errorf("NewStore(%s) succeeded, want error", ttl)
		}
	}
}

func TestIssueValidateRoundTrip(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	tok, expires, err := s.Issue("obj-1", testDataset, "user-123", "https://issuer.example.org")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if want := refTime.Add(testTTL); !expires.Equal(want) {
		t.Errorf("expires = %s, want %s", expires, want)
	}

	sess, err := s.Validate(tok, "obj-1")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sess.Subject != "user-123" || sess.Dataset != testDataset || sess.Issuer != "https://issuer.example.org" {
		t.Errorf("session = %+v, want subject/dataset/issuer of the issued token", sess)
	}
}

func TestIssueRequiresObjectDatasetSubject(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	cases := map[string][3]string{
		"no object":  {"", testDataset, "user-123"},
		"no dataset": {"obj-1", "", "user-123"},
		"no subject": {"obj-1", testDataset, ""},
	}
	for name, args := range cases {
		if _, _, err := s.Issue(args[0], args[1], args[2], "iss"); err == nil {
			t.Errorf("Issue with %s succeeded, want error", name)
		}
	}
}

func TestValidateUnknownToken(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	if _, err := s.Validate("never-issued", "obj-1"); !errors.Is(err, ErrUnknownToken) {
		t.Fatalf("error = %v, want ErrUnknownToken", err)
	}
}

func TestValidateWrongObject(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	tok, _, err := s.Issue("obj-1", testDataset, "user-123", "iss")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Validate(tok, "obj-2"); !errors.Is(err, ErrWrongObject) {
		t.Fatalf("error = %v, want ErrWrongObject", err)
	}
	// The mismatch must not consume the token.
	if _, err := s.Validate(tok, "obj-1"); err != nil {
		t.Fatalf("Validate after mismatch: %v", err)
	}
}

// TestValidateTTLBoundary pins the expiry boundary: valid strictly before
// expiry, expired at it.
func TestValidateTTLBoundary(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	tok, expires, err := s.Issue("obj-1", testDataset, "user-123", "iss")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	now = expires.Add(-time.Second)
	if _, err := s.Validate(tok, "obj-1"); err != nil {
		t.Fatalf("just before expiry: %v", err)
	}

	now = expires
	if _, err := s.Validate(tok, "obj-1"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("at expiry: error = %v, want ErrTokenExpired", err)
	}

	// Once expired the token is gone for good, even if the clock rewinds.
	now = refTime
	if _, err := s.Validate(tok, "obj-1"); !errors.Is(err, ErrUnknownToken) {
		t.Fatalf("after expiry purge: error = %v, want ErrUnknownToken", err)
	}
}

func TestIssuePurgesExpiredSessions(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	stale, _, err := s.Issue("obj-1", testDataset, "user-123", "iss")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	now = refTime.Add(testTTL + time.Second)
	if _, _, err := s.Issue("obj-2", testDataset, "user-123", "iss"); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	s.mu.Lock()
	_, staleAlive := s.sessions[stale]
	size := len(s.sessions)
	s.mu.Unlock()
	if staleAlive || size != 1 {
		t.Errorf("stale session survived the purge: alive=%v, size=%d", staleAlive, size)
	}
}

// TestRevokeBySubjectDataset revokes one (subject, dataset) and pins that only
// that user's sessions for that dataset go: their other dataset survives, and
// another user's session for the same dataset survives.
func TestRevokeBySubjectDataset(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	const otherDataset = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000002"
	revoked, _, err := s.Issue("obj-1", testDataset, "alice", "iss")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	keptDataset, _, err := s.Issue("obj-2", otherDataset, "alice", "iss")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	keptUser, _, err := s.Issue("obj-1", testDataset, "bob", "iss")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if n := s.Revoke("alice", testDataset); n != 1 {
		t.Errorf("Revoke count = %d, want 1", n)
	}
	if _, err := s.Validate(revoked, "obj-1"); !errors.Is(err, ErrUnknownToken) {
		t.Errorf("revoked token: error = %v, want ErrUnknownToken", err)
	}
	if _, err := s.Validate(keptDataset, "obj-2"); err != nil {
		t.Errorf("alice's other dataset was revoked: %v", err)
	}
	if _, err := s.Validate(keptUser, "obj-1"); err != nil {
		t.Errorf("bob's session for the same dataset was revoked: %v", err)
	}
}

// TestRevokeSubjectAll revokes with an empty dataset and pins that all of the
// subject's sessions go while another subject's are untouched.
func TestRevokeSubjectAll(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	const otherDataset = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000002"
	a1, _, _ := s.Issue("obj-1", testDataset, "alice", "iss")
	a2, _, _ := s.Issue("obj-2", otherDataset, "alice", "iss")
	bob, _, _ := s.Issue("obj-1", testDataset, "bob", "iss")

	if n := s.Revoke("alice", ""); n != 2 {
		t.Errorf("Revoke count = %d, want 2", n)
	}
	for _, tok := range []string{a1, a2} {
		if _, err := s.Validate(tok, "obj-1"); !errors.Is(err, ErrUnknownToken) {
			t.Errorf("alice's token survived a full revoke: %v", err)
		}
	}
	if _, err := s.Validate(bob, "obj-1"); err != nil {
		t.Errorf("bob's session was revoked: %v", err)
	}
}

func TestRevokeUnknownSubjectRemovesNothing(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	if _, _, err := s.Issue("obj-1", testDataset, "alice", "iss"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if n := s.Revoke("nobody", ""); n != 0 {
		t.Errorf("Revoke of unknown subject = %d, want 0", n)
	}
	if n := s.Revoke("alice", "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD999999"); n != 0 {
		t.Errorf("Revoke of subject's non-granted dataset = %d, want 0", n)
	}
}

// TestRevokeLeavesComplement is the set property: after revoking (subject,
// dataset), the surviving sessions are exactly those that did not match, and the
// count returned equals the number removed.
func TestRevokeLeavesComplement(t *testing.T) {
	subjects := []string{"alice", "bob", "carol"}
	datasets := []string{
		"https://example.org/d/1",
		"https://example.org/d/2",
		"https://example.org/d/3",
	}

	rapid.Check(t, func(rt *rapid.T) {
		now := refTime
		s := storeAt(t, &now)

		type binding struct {
			tok     string
			object  string
			subject string
			dataset string
		}
		n := rapid.IntRange(0, 40).Draw(rt, "sessions")
		bindings := make([]binding, 0, n)
		for i := range n {
			subject := rapid.SampledFrom(subjects).Draw(rt, "subject")
			dataset := rapid.SampledFrom(datasets).Draw(rt, "dataset")
			object := fmt.Sprintf("obj-%d", i)
			tok, _, err := s.Issue(object, dataset, subject, "iss")
			if err != nil {
				rt.Fatalf("Issue: %v", err)
			}
			bindings = append(bindings, binding{tok, object, subject, dataset})
		}

		revSubject := rapid.SampledFrom(subjects).Draw(rt, "revoke subject")
		revDataset := rapid.SampledFrom(append([]string{""}, datasets...)).Draw(rt, "revoke dataset")

		matches := func(b binding) bool {
			return b.subject == revSubject && (revDataset == "" || b.dataset == revDataset)
		}
		want := 0
		for _, b := range bindings {
			if matches(b) {
				want++
			}
		}

		if got := s.Revoke(revSubject, revDataset); got != want {
			rt.Fatalf("Revoke count = %d, want %d", got, want)
		}
		for _, b := range bindings {
			_, err := s.Validate(b.tok, b.object)
			if matches(b) {
				if !errors.Is(err, ErrUnknownToken) {
					rt.Errorf("matched session %+v survived: err = %v", b, err)
				}
			} else if err != nil {
				rt.Errorf("unmatched session %+v was revoked: err = %v", b, err)
			}
		}
	})
}

// TestTokensAreUniqueAndOpaque draws many tokens and checks they are distinct,
// URL-safe, and long enough to carry the full 256 bits of entropy.
func TestTokensAreUniqueAndOpaque(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	seen := make(map[string]bool)
	rapid.Check(t, func(rt *rapid.T) {
		object := rapid.StringMatching(`obj-[a-z0-9]{1,10}`).Draw(rt, "object")
		subject := rapid.StringMatching(`user-[a-z0-9]{1,10}`).Draw(rt, "subject")

		tok, _, err := s.Issue(object, testDataset, subject, "iss")
		if err != nil {
			rt.Fatalf("Issue: %v", err)
		}
		if len(tok) < 43 { // 32 bytes in unpadded base64url
			rt.Fatalf("token %q is shorter than 32 bytes of entropy", tok)
		}
		if seen[tok] {
			rt.Fatalf("token %q issued twice", tok)
		}
		seen[tok] = true

		if _, err := s.Validate(tok, object); err != nil {
			rt.Fatalf("Validate: %v", err)
		}
		if object != "obj-x" {
			if _, err := s.Validate(tok, "obj-x"); !errors.Is(err, ErrWrongObject) {
				rt.Fatalf("cross-object error = %v, want ErrWrongObject", err)
			}
		}
	})
}

// TestConcurrentIssueValidateRevoke exercises the store from many goroutines;
// run with -race this pins the locking discipline across all three operations.
func TestConcurrentIssueValidateRevoke(t *testing.T) {
	s, err := NewStore(testTTL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subject := fmt.Sprintf("user-%d", g)
			for range 100 {
				tok, _, err := s.Issue("obj-1", testDataset, subject, "iss")
				if err != nil {
					t.Errorf("Issue: %v", err)

					return
				}
				if _, err := s.Validate(tok, "obj-1"); err != nil {
					t.Errorf("Validate: %v", err)

					return
				}
				s.Revoke(subject, testDataset)
			}
		}()
	}
	wg.Wait()
}
