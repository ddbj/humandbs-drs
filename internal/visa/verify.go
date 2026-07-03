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

// Verify checks a Visa Document Token and returns its claims. It rejects, in
// order: a header outside the shared allowlist (before any key is consulted), a
// bad signature or unknown `kid`, an absent required claim, and a temporal
// violation. Visas do not require a `typ` header (it is OPTIONAL in the spec),
// so none is enforced.
func (v *Verifier) Verify(raw string) (Claims, error) {
	tok, err := v.parseVerified(raw, "")
	if err != nil {
		return Claims{}, err
	}

	claims, err := claimsFromToken(tok)
	if err != nil {
		return Claims{}, err
	}
	if err := v.checkTemporal(tok, claims.IssuedAt, claims.Expires); err != nil {
		return Claims{}, err
	}

	return claims, nil
}

// parseVerified runs the checks shared by visa and passport verification: the
// RS256/ES256 allowlist and crit rejection read from the protected header before
// any key is consulted, the expected `typ` when one is required, the signature
// against the key selected by `kid`, and the absence of an `aud` claim.
// Temporal validation is left to the caller so it uses the injected clock.
func (v *Verifier) parseVerified(raw, wantTyp string) (jwt.Token, error) {
	hdr, err := protectedHeader(raw)
	if err != nil {
		return nil, err
	}
	if !allowedAlg(hdr.Alg) {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, hdr.Alg)
	}
	if len(hdr.Crit) > 0 {
		return nil, fmt.Errorf("%w: %v", ErrCriticalHeader, hdr.Crit)
	}
	if wantTyp != "" && !typeMatches(hdr.Typ, wantTyp) {
		return nil, fmt.Errorf("%w: typ %q, want %q", ErrUnexpectedTokenType, hdr.Typ, wantTyp)
	}

	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(v.keys, jws.WithRequireKid(true)),
		jwt.WithValidate(false),
	)
	if err != nil {
		return nil, fmt.Errorf("visa: verify token: %w", err)
	}

	if aud, ok := tok.Audience(); ok && len(aud) > 0 {
		return nil, fmt.Errorf("%w: aud %q", ErrAudiencePresent, aud)
	}

	return tok, nil
}

// checkTemporal rejects an expired or not-yet-valid token. A token is valid
// while now is before exp, iat is not beyond now, and any nbf is not beyond now,
// each widened by the leeway.
func (v *Verifier) checkTemporal(tok jwt.Token, iat, exp time.Time) error {
	now := time.Now()
	if v.now != nil {
		now = v.now()
	}

	if !now.Before(exp.Add(v.leeway)) {
		return fmt.Errorf("%w: exp %s, now %s", ErrTokenExpired, exp.UTC(), now.UTC())
	}
	if iat.After(now.Add(v.leeway)) {
		return fmt.Errorf("%w: iat %s, now %s", ErrTokenNotYetIssued, iat.UTC(), now.UTC())
	}
	if nbf, ok := tok.NotBefore(); ok && nbf.After(now.Add(v.leeway)) {
		return fmt.Errorf("%w: nbf %s, now %s", ErrTokenNotYetValid, nbf.UTC(), now.UTC())
	}

	return nil
}

// typeMatches compares a `typ` header value against the expected media type
// using the RFC 7515 §4.1.9 rules: comparison is case-insensitive and a value
// without a slash is equivalent to the same value under "application/".
func typeMatches(got, want string) bool {
	normalize := func(t string) string {
		return strings.TrimPrefix(strings.ToLower(t), "application/")
	}

	return got != "" && normalize(got) == normalize(want)
}

// tokenHeader is the subset of a JWS protected header inspected before the
// signature is verified.
type tokenHeader struct {
	Alg  string   `json:"alg"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
}

// protectedHeader reads the protected header of a compact JWS without verifying
// the signature, so an untrusted algorithm or unsupported extension is rejected
// before any key material is used.
func protectedHeader(raw string) (tokenHeader, error) {
	first, _, ok := strings.Cut(raw, ".")
	if !ok || first == "" {
		return tokenHeader{}, fmt.Errorf("%w: not a compact JWS", ErrMalformedToken)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		return tokenHeader{}, fmt.Errorf("%w: header is not base64url", ErrMalformedToken)
	}

	var header tokenHeader
	if err := json.Unmarshal(decoded, &header); err != nil {
		return tokenHeader{}, fmt.Errorf("%w: header is not JSON", ErrMalformedToken)
	}
	if header.Alg == "" {
		return tokenHeader{}, fmt.Errorf("%w: header has no alg", ErrMalformedToken)
	}

	return header, nil
}

// claimsFromToken extracts the required standard claims and the Visa Object,
// reporting any that are absent.
func claimsFromToken(tok jwt.Token) (Claims, error) {
	iss, sub, iat, exp, err := standardClaimsFromToken(tok)
	if err != nil {
		return Claims{}, err
	}

	obj, err := visaFromToken(tok)
	if err != nil {
		return Claims{}, err
	}

	jti, _ := tok.JwtID()

	return Claims{Issuer: iss, Subject: sub, IssuedAt: iat, Expires: exp, ID: jti, Visa: obj}, nil
}

// standardClaimsFromToken extracts the standard claims the specification marks
// REQUIRED on both visas and passports, reporting any that are absent.
func standardClaimsFromToken(tok jwt.Token) (iss, sub string, iat, exp time.Time, err error) {
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
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("%w: %s", ErrMissingClaim, strings.Join(missing, ", "))
	}

	return iss, sub, iat, exp, nil
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
