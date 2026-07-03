// Package token implements the opaque session tokens of authorized delivery
// (architecture.md § "配信設計"): the access endpoint issues one after the
// Clearinghouse grants a dataset, and the delivery endpoint validates it on
// every request. Tokens are held in a server-side in-memory store — the server
// runs as a single process (requirements.md § 5.3) — so a restart naturally
// revokes them, and each token is bound to the object, dataset, and subject it
// was issued for. Binding the dataset lets Revoke reflect a DAC grant removal
// immediately: revoking (subject, dataset) drops exactly the sessions the lost
// grant covered (requirements.md § 4.7).
package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Validation outcomes, distinguished so the delivery endpoint can log why a
// request was refused. All of them deny access.
var (
	// ErrUnknownToken reports a token that was never issued, was purged, or
	// did not survive a restart.
	ErrUnknownToken = errors.New("token: unknown token")
	// ErrTokenExpired reports a token past its TTL.
	ErrTokenExpired = errors.New("token: token expired")
	// ErrWrongObject reports a token presented for an object it was not
	// issued for.
	ErrWrongObject = errors.New("token: token is not valid for this object")
)

// tokenBytes is the entropy of a token: 32 bytes (256 bits) of crypto/rand,
// making guessing infeasible.
const tokenBytes = 32

// session is what one token authorizes: one object of one dataset for one
// subject until expiry.
type session struct {
	objectID string
	dataset  string
	subject  string
	issuer   string
	expires  time.Time
}

// Session is the delivery context a valid token carries: the subject and
// dataset the download is for and the issuer whose visa granted it. The delivery
// endpoint uses it for the audit trail (requirements.md § 5.1).
type Session struct {
	Subject string
	Dataset string
	Issuer  string
}

// Store issues and validates session tokens with a fixed TTL.
type Store struct {
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	sessions map[string]session
}

// Option configures a Store.
type Option func(*Store)

// WithClock overrides the clock used to stamp and check expiry. It exists to
// make TTL boundaries testable; production callers omit it.
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		s.now = now
	}
}

// NewStore builds a Store whose tokens live for ttl.
func NewStore(ttl time.Duration, opts ...Option) (*Store, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("token: store requires a positive ttl, got %s", ttl)
	}

	s := &Store{ttl: ttl, now: time.Now, sessions: make(map[string]session)}
	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Issue mints a fresh token authorizing objectID of dataset for subject and
// returns it with its expiry. dataset is the object's dataset resource URL, so
// Revoke can drop a subject's sessions for one dataset; issuer records which
// trusted issuer's visa granted the access, for the audit trail.
func (s *Store) Issue(objectID, dataset, subject, issuer string) (string, time.Time, error) {
	if objectID == "" || dataset == "" || subject == "" {
		return "", time.Time{}, errors.New("token: issue requires an object ID, a dataset, and a subject")
	}

	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, fmt.Errorf("token: read randomness: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.purgeLocked(now)
	expires := now.Add(s.ttl)
	s.sessions[tok] = session{objectID: objectID, dataset: dataset, subject: subject, issuer: issuer, expires: expires}

	return tok, expires, nil
}

// Validate checks that tok was issued for objectID and has not expired, and
// returns the session's delivery context. A token is valid strictly before its
// expiry. An expired token is purged and reports ErrTokenExpired; a token issued
// for another object reports ErrWrongObject without being consumed.
func (s *Store) Validate(tok, objectID string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[tok]
	if !ok {
		return Session{}, ErrUnknownToken
	}
	if !s.now().Before(sess.expires) {
		delete(s.sessions, tok)

		return Session{}, ErrTokenExpired
	}
	if sess.objectID != objectID {
		return Session{}, ErrWrongObject
	}

	return Session{Subject: sess.subject, Dataset: sess.dataset, Issuer: sess.issuer}, nil
}

// Revoke drops the sessions of subject, immediately denying their in-flight
// downloads from the next request (requirements.md § 4.7). When dataset is
// non-empty only that subject's sessions for that dataset are dropped, matching
// a single DAC grant removal; an empty dataset drops all of the subject's
// sessions. It returns the number of sessions removed.
func (s *Store) Revoke(subject, dataset string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	revoked := 0
	for tok, sess := range s.sessions {
		if sess.subject != subject {
			continue
		}
		if dataset != "" && sess.dataset != dataset {
			continue
		}
		delete(s.sessions, tok)
		revoked++
	}

	return revoked
}

// purgeLocked drops expired sessions so the store's memory is bounded by the
// number of tokens issued per TTL window. Callers hold s.mu.
func (s *Store) purgeLocked(now time.Time) {
	for tok, sess := range s.sessions {
		if !now.Before(sess.expires) {
			delete(s.sessions, tok)
		}
	}
}
