package visa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Verifier validates Visa Document Tokens against a JWK set. It enforces the
// RS256/ES256 algorithm allowlist, verifies the signature with the key selected
// by `kid`, and checks the temporal claims itself using an injectable clock so
// the exp/iat boundaries are deterministic.
type Verifier struct {
	keys   jwk.Set
	now    func() time.Time
	leeway time.Duration
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithClock overrides the clock used for exp/iat checks. It exists chiefly to
// make temporal boundaries testable; production callers omit it and get the wall
// clock.
func WithClock(now func() time.Time) VerifierOption {
	return func(v *Verifier) {
		v.now = now
	}
}

// WithLeeway allows a symmetric tolerance when comparing exp and iat against the
// clock, absorbing small clock skew between issuer and verifier.
func WithLeeway(d time.Duration) VerifierOption {
	return func(v *Verifier) {
		v.leeway = d
	}
}

// NewVerifier builds a Verifier over keys, a JWK set whose keys carry the pinned
// signing algorithm and `kid` (see PublicJWKS).
func NewVerifier(keys jwk.Set, opts ...VerifierOption) *Verifier {
	v := &Verifier{keys: keys}
	for _, opt := range opts {
		opt(v)
	}

	return v
}

// Verify checks raw and returns its claims. It rejects, in order: a header
// algorithm outside the allowlist (before any key is consulted), a bad signature
// or unknown `kid`, an absent required claim, an expired token, and a token
// issued in the future.
func (v *Verifier) Verify(raw string) (Claims, error) {
	alg, err := protectedAlg(raw)
	if err != nil {
		return Claims{}, err
	}
	if !allowedAlg(alg) {
		return Claims{}, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, alg)
	}

	// The signature is verified here; temporal validation is deferred to this
	// method so it uses the injected clock and reports the sentinel errors.
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(v.keys, jws.WithRequireKid(true)),
		jwt.WithValidate(false),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("visa: verify token: %w", err)
	}

	claims, err := claimsFromToken(tok)
	if err != nil {
		return Claims{}, err
	}
	if err := v.checkTemporal(claims); err != nil {
		return Claims{}, err
	}

	return claims, nil
}

// checkTemporal rejects an expired or not-yet-issued token. A token is valid
// while now is before exp and iat is not beyond now, each widened by the leeway.
func (v *Verifier) checkTemporal(c Claims) error {
	now := time.Now()
	if v.now != nil {
		now = v.now()
	}

	if !now.Before(c.Expires.Add(v.leeway)) {
		return fmt.Errorf("%w: exp %s, now %s", ErrTokenExpired, c.Expires.UTC(), now.UTC())
	}
	if c.IssuedAt.After(now.Add(v.leeway)) {
		return fmt.Errorf("%w: iat %s, now %s", ErrTokenNotYetIssued, c.IssuedAt.UTC(), now.UTC())
	}

	return nil
}

// protectedAlg reads the `alg` of a compact JWS from its protected header without
// verifying the signature, so an untrusted algorithm is rejected before any key
// material is used.
func protectedAlg(raw string) (string, error) {
	first, _, ok := strings.Cut(raw, ".")
	if !ok || first == "" {
		return "", fmt.Errorf("%w: not a compact JWS", ErrMalformedToken)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		return "", fmt.Errorf("%w: header is not base64url", ErrMalformedToken)
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return "", fmt.Errorf("%w: header is not JSON", ErrMalformedToken)
	}
	if header.Alg == "" {
		return "", fmt.Errorf("%w: header has no alg", ErrMalformedToken)
	}

	return header.Alg, nil
}

// claimsFromToken extracts the required standard claims and the Visa Object,
// reporting any that are absent.
func claimsFromToken(tok jwt.Token) (Claims, error) {
	iss, hasIss := tok.Issuer()
	sub, hasSub := tok.Subject()
	iat, hasIat := tok.IssuedAt()
	exp, hasExp := tok.Expiration()

	var missing []string
	if !hasIss || iss == "" {
		missing = append(missing, "iss")
	}
	if !hasSub || sub == "" {
		missing = append(missing, "sub")
	}
	if !hasIat {
		missing = append(missing, "iat")
	}
	if !hasExp {
		missing = append(missing, "exp")
	}
	if len(missing) > 0 {
		return Claims{}, fmt.Errorf("%w: %s", ErrMissingClaim, strings.Join(missing, ", "))
	}

	obj, err := visaFromToken(tok)
	if err != nil {
		return Claims{}, err
	}

	jti, _ := tok.JwtID()

	return Claims{Issuer: iss, Subject: sub, IssuedAt: iat, Expires: exp, ID: jti, Visa: obj}, nil
}

// visaFromToken decodes the ga4gh_visa_v1 claim into an Object by re-encoding the
// parsed claim value, which preserves the verbatim conditions payload.
func visaFromToken(tok jwt.Token) (Object, error) {
	if !tok.Has(claimVisa) {
		return Object{}, fmt.Errorf("%w: %s", ErrMissingClaim, claimVisa)
	}

	var raw any
	if err := tok.Get(claimVisa, &raw); err != nil {
		return Object{}, fmt.Errorf("visa: read %s claim: %w", claimVisa, err)
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return Object{}, fmt.Errorf("visa: re-encode %s claim: %w", claimVisa, err)
	}

	var obj Object
	if err := json.Unmarshal(encoded, &obj); err != nil {
		return Object{}, fmt.Errorf("visa: decode %s claim: %w", claimVisa, err)
	}

	return obj, nil
}
