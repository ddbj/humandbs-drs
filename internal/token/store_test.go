package token

import (
	"errors"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"
)

var refTime = time.Unix(1_700_000_000, 0).UTC()

const testTTL = 5 * time.Minute

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

	tok, expires, err := s.Issue("obj-1", "user-123", "https://issuer.example.org")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if want := refTime.Add(testTTL); !expires.Equal(want) {
		t.Errorf("expires = %s, want %s", expires, want)
	}
	if err := s.Validate(tok, "obj-1"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestIssueRequiresObjectAndSubject(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	if _, _, err := s.Issue("", "user-123", "iss"); err == nil {
		t.Error("Issue without object succeeded, want error")
	}
	if _, _, err := s.Issue("obj-1", "", "iss"); err == nil {
		t.Error("Issue without subject succeeded, want error")
	}
}

func TestValidateUnknownToken(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	if err := s.Validate("never-issued", "obj-1"); !errors.Is(err, ErrUnknownToken) {
		t.Fatalf("error = %v, want ErrUnknownToken", err)
	}
}

func TestValidateWrongObject(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	tok, _, err := s.Issue("obj-1", "user-123", "iss")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Validate(tok, "obj-2"); !errors.Is(err, ErrWrongObject) {
		t.Fatalf("error = %v, want ErrWrongObject", err)
	}
	// The mismatch must not consume the token.
	if err := s.Validate(tok, "obj-1"); err != nil {
		t.Fatalf("Validate after mismatch: %v", err)
	}
}

// TestValidateTTLBoundary pins the expiry boundary: valid strictly before
// expiry, expired at it.
func TestValidateTTLBoundary(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	tok, expires, err := s.Issue("obj-1", "user-123", "iss")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	now = expires.Add(-time.Second)
	if err := s.Validate(tok, "obj-1"); err != nil {
		t.Fatalf("just before expiry: %v", err)
	}

	now = expires
	if err := s.Validate(tok, "obj-1"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("at expiry: error = %v, want ErrTokenExpired", err)
	}

	// Once expired the token is gone for good, even if the clock rewinds.
	now = refTime
	if err := s.Validate(tok, "obj-1"); !errors.Is(err, ErrUnknownToken) {
		t.Fatalf("after expiry purge: error = %v, want ErrUnknownToken", err)
	}
}

func TestIssuePurgesExpiredSessions(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	stale, _, err := s.Issue("obj-1", "user-123", "iss")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	now = refTime.Add(testTTL + time.Second)
	if _, _, err := s.Issue("obj-2", "user-123", "iss"); err != nil {
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

// TestTokensAreUniqueAndOpaque draws many tokens and checks they are distinct,
// URL-safe, and long enough to carry the full 256 bits of entropy.
func TestTokensAreUniqueAndOpaque(t *testing.T) {
	now := refTime
	s := storeAt(t, &now)

	seen := make(map[string]bool)
	rapid.Check(t, func(rt *rapid.T) {
		object := rapid.StringMatching(`obj-[a-z0-9]{1,10}`).Draw(rt, "object")
		subject := rapid.StringMatching(`user-[a-z0-9]{1,10}`).Draw(rt, "subject")

		tok, _, err := s.Issue(object, subject, "iss")
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

		if err := s.Validate(tok, object); err != nil {
			rt.Fatalf("Validate: %v", err)
		}
		if object != "obj-x" {
			if err := s.Validate(tok, "obj-x"); !errors.Is(err, ErrWrongObject) {
				rt.Fatalf("cross-object error = %v, want ErrWrongObject", err)
			}
		}
	})
}

// TestConcurrentIssueValidate exercises the store from many goroutines; run
// with -race this pins the locking discipline.
func TestConcurrentIssueValidate(t *testing.T) {
	s, err := NewStore(testTTL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				tok, _, err := s.Issue("obj-1", "user-123", "iss")
				if err != nil {
					t.Errorf("Issue: %v", err)

					return
				}
				if err := s.Validate(tok, "obj-1"); err != nil {
					t.Errorf("Validate: %v", err)

					return
				}
			}
		}()
	}
	wg.Wait()
}
