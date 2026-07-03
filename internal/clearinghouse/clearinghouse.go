// Package clearinghouse implements the GA4GH Passport Clearinghouse of the DRS
// server (architecture.md § "Clearinghouse 設計"): it verifies the Passports
// presented to the access endpoints and decides whether they grant access to a
// dataset.
//
// Trust is rooted in configuration, not in the tokens: each trusted issuer is
// pinned to a JWK set fetched out-of-band at startup, a token's `iss` selects
// the pinned keys, and a token's `jku` is only compared against the pinned
// JWKS URL — never fetched. Passports that fail verification reject the whole
// request (ga4gh_passport_v1 § 8.1); visas that fail verification are ignored.
package clearinghouse

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

// Authorization outcomes. The DRS handler maps ErrNoValidPassport to 401 (the
// request carried no usable credential) and ErrNotAuthorized to 403 (the
// credential is valid but grants no access to the dataset).
var (
	ErrNoValidPassport = errors.New("clearinghouse: no valid passport presented")
	ErrNotAuthorized   = errors.New("clearinghouse: passport grants no access to the dataset")
)

// Request-size caps. Exceeding one is a verification failure, not a truncated
// best effort (architecture.md § "Clearinghouse 設計").
const (
	// maxPassports bounds the passports array of one request.
	maxPassports = 8
	// maxVisasPerPassport bounds the ga4gh_passport_v1 array of one passport.
	maxVisasPerPassport = 64
)

// allowedBy are the Visa Object `by` values accepted for ControlledAccessGrants:
// organizational assertions. `self` and `peer` (and an absent `by`, whose
// authority is unknown) do not substantiate controlled access
// (ga4gh_passport_v1 § "by").
var allowedBy = map[string]bool{"dac": true, "so": true, "system": true}

// Issuer is a trusted issuer: its URL (matched verbatim against `iss` claims),
// the JWKS URL its keys were pinned from (matched verbatim against `jku`
// headers), and the pinned keys themselves.
type Issuer struct {
	URL     string
	JWKSURL string
	Keys    jwk.Set
}

// Grant identifies the visa that authorized a request: its subject, issuer,
// and jti, the identity a session token is bound to and the audit trail of the
// authorization decision.
type Grant struct {
	Subject string
	Issuer  string
	JTI     string
}

// issuerEntry is the per-issuer verification state.
type issuerEntry struct {
	jwksURL  string
	verifier *visa.Verifier
}

// Clearinghouse verifies passports and visas against a fixed set of trusted
// issuers and evaluates dataset authorization.
type Clearinghouse struct {
	issuers map[string]issuerEntry
	clock   func() time.Time
	leeway  time.Duration
	logger  *slog.Logger
}

// Option configures a Clearinghouse.
type Option func(*Clearinghouse)

// WithClock overrides the clock used for temporal claim checks. It exists to
// make expiry boundaries testable; production callers omit it.
func WithClock(now func() time.Time) Option {
	return func(c *Clearinghouse) {
		c.clock = now
	}
}

// WithLeeway allows a symmetric tolerance on temporal claim checks, absorbing
// clock skew between the issuers and this server.
func WithLeeway(d time.Duration) Option {
	return func(c *Clearinghouse) {
		c.leeway = d
	}
}

// WithLogger sets the logger that records, at debug level, why each rejected
// passport or visa was rejected.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Clearinghouse) {
		c.logger = logger
	}
}

// New builds a Clearinghouse trusting exactly the given issuers.
func New(issuers []Issuer, opts ...Option) (*Clearinghouse, error) {
	if len(issuers) == 0 {
		return nil, errors.New("clearinghouse: at least one trusted issuer is required")
	}

	c := &Clearinghouse{issuers: make(map[string]issuerEntry, len(issuers)), logger: slog.Default()}
	for _, opt := range opts {
		opt(c)
	}

	verifierOpts := []visa.VerifierOption{visa.WithLeeway(c.leeway)}
	if c.clock != nil {
		verifierOpts = append(verifierOpts, visa.WithClock(c.clock))
	}
	for _, iss := range issuers {
		if iss.URL == "" || iss.JWKSURL == "" {
			return nil, fmt.Errorf("clearinghouse: trusted issuer %q needs both an issuer URL and a JWKS URL", iss.URL)
		}
		if iss.Keys == nil || iss.Keys.Len() == 0 {
			return nil, fmt.Errorf("clearinghouse: trusted issuer %q has no pinned keys", iss.URL)
		}
		if _, dup := c.issuers[iss.URL]; dup {
			return nil, fmt.Errorf("clearinghouse: duplicate trusted issuer %q", iss.URL)
		}
		c.issuers[iss.URL] = issuerEntry{
			jwksURL:  iss.JWKSURL,
			verifier: visa.NewVerifier(iss.Keys, verifierOpts...),
		}
	}

	return c, nil
}

// Authorize verifies the presented passports and decides whether any embedded
// visa grants access to the dataset named by datasetURL. Every passport must
// verify — one failing envelope rejects the whole request with
// ErrNoValidPassport — while a failing visa is skipped. When no verified visa
// grants the dataset, the result is ErrNotAuthorized.
func (c *Clearinghouse) Authorize(ctx context.Context, passports []string, datasetURL string) (Grant, error) {
	if len(passports) == 0 {
		return Grant{}, fmt.Errorf("%w: no passports in request", ErrNoValidPassport)
	}
	if len(passports) > maxPassports {
		return Grant{}, fmt.Errorf("%w: %d passports exceed the limit of %d", ErrNoValidPassport, len(passports), maxPassports)
	}

	var grant Grant
	granted := false
	for i, raw := range passports {
		_, visas, err := c.verifyPassport(ctx, raw)
		if err != nil {
			c.logger.DebugContext(ctx, "passport rejected", "index", i, "error", err)

			return Grant{}, fmt.Errorf("%w: passport %d: %w", ErrNoValidPassport, i, err)
		}
		if !granted {
			if g, ok := c.grantIn(ctx, visas, datasetURL); ok {
				grant = g
				granted = true
			}
		}
	}
	if !granted {
		return Grant{}, fmt.Errorf("%w: %s", ErrNotAuthorized, datasetURL)
	}

	c.logger.DebugContext(ctx, "access granted",
		"dataset", datasetURL, "subject", grant.Subject, "issuer", grant.Issuer, "jti", grant.JTI)

	return grant, nil
}

// verifyPassport verifies one passport envelope and returns its claims along
// with the embedded visas that verified. An envelope failure is an error; a
// visa failure is logged and the visa dropped.
func (c *Clearinghouse) verifyPassport(ctx context.Context, raw string) (visa.PassportClaims, []visa.Claims, error) {
	entry, peek, err := c.trustedEntry(raw)
	if err != nil {
		return visa.PassportClaims{}, nil, err
	}
	// A passport's jku is optional; when present it must be the pinned URL.
	if peek.jku != "" && peek.jku != entry.jwksURL {
		return visa.PassportClaims{}, nil, fmt.Errorf("jku %q is not the pinned JWKS URL of issuer %q", peek.jku, peek.issuer)
	}

	env, err := entry.verifier.VerifyPassport(raw)
	if err != nil {
		return visa.PassportClaims{}, nil, err
	}
	if env.Issuer != peek.issuer {
		return visa.PassportClaims{}, nil, fmt.Errorf("verified iss %q differs from presented iss %q", env.Issuer, peek.issuer)
	}
	if len(env.Visas) > maxVisasPerPassport {
		return visa.PassportClaims{}, nil, fmt.Errorf("%d visas exceed the limit of %d", len(env.Visas), maxVisasPerPassport)
	}

	verified := make([]visa.Claims, 0, len(env.Visas))
	for i, rawVisa := range env.Visas {
		claims, err := c.verifyVisa(rawVisa, env)
		if err != nil {
			c.logger.DebugContext(ctx, "visa ignored", "index", i, "error", err)

			continue
		}
		verified = append(verified, claims)
	}

	return env, verified, nil
}

// verifyVisa verifies one embedded Visa Document Token: trusted issuer, jku
// pinned, signature and temporal claims (via the per-issuer verifier), subject
// bound to the passport, and the REQUIRED Visa Object fields present.
func (c *Clearinghouse) verifyVisa(raw string, env visa.PassportClaims) (visa.Claims, error) {
	entry, peek, err := c.trustedEntry(raw)
	if err != nil {
		return visa.Claims{}, err
	}
	// A Visa Document Token must carry a jku (AAI § Conformance for Visa
	// Issuers), and it must be the pinned URL — never one to fetch.
	if peek.jku == "" {
		return visa.Claims{}, errors.New("visa has no jku header")
	}
	if peek.jku != entry.jwksURL {
		return visa.Claims{}, fmt.Errorf("jku %q is not the pinned JWKS URL of issuer %q", peek.jku, peek.issuer)
	}

	claims, err := entry.verifier.Verify(raw)
	if err != nil {
		return visa.Claims{}, err
	}
	if claims.Issuer != peek.issuer {
		return visa.Claims{}, fmt.Errorf("verified iss %q differs from presented iss %q", claims.Issuer, peek.issuer)
	}
	// Visas of another subject are not this user's: linking identities across
	// subjects (LinkedIdentities) is not supported.
	if claims.Subject != env.Subject {
		return visa.Claims{}, fmt.Errorf("visa sub %q differs from passport sub %q", claims.Subject, env.Subject)
	}
	// type, asserted, value, and source are REQUIRED on every Visa Object; an
	// asserted of 0 (the epoch) is treated as absent.
	if claims.Visa.Type == "" || claims.Visa.Value == "" || claims.Visa.Source == "" || claims.Visa.Asserted == 0 {
		return visa.Claims{}, errors.New("visa object misses a required field (type, asserted, value, source)")
	}

	return claims, nil
}

// grantIn reports whether one of the verified visas of a single passport
// grants datasetURL, and if so which one. Conditions are evaluated against the
// other verified visas of the same passport that carry no conditions
// themselves.
func (c *Clearinghouse) grantIn(ctx context.Context, visas []visa.Claims, datasetURL string) (Grant, bool) {
	var pool []visa.Object
	for _, v := range visas {
		if !conditionsPresent(v.Visa.Conditions) {
			pool = append(pool, v.Visa)
		}
	}

	for _, v := range visas {
		if v.Visa.Type != visa.TypeControlledAccessGrants {
			continue
		}
		if v.Visa.Value != datasetURL {
			continue
		}
		if !allowedBy[v.Visa.By] {
			c.logger.DebugContext(ctx, "grant visa ignored", "jti", v.ID, "reason", "by not allowed", "by", v.Visa.By)

			continue
		}
		if conditionsPresent(v.Visa.Conditions) {
			dnf, err := compileConditions(v.Visa.Conditions)
			if err != nil {
				c.logger.DebugContext(ctx, "grant visa ignored", "jti", v.ID, "reason", "malformed conditions", "error", err)

				continue
			}
			if !evalConditions(dnf, pool) {
				c.logger.DebugContext(ctx, "grant visa ignored", "jti", v.ID, "reason", "conditions not satisfied")

				continue
			}
		}

		return Grant{Subject: v.Subject, Issuer: v.Issuer, JTI: v.ID}, true
	}

	return Grant{}, false
}

// tokenPeek is the unverified excerpt of a compact JWS used to select the
// trusted issuer and pin the jku. Both values are covered by the signature, so
// once verification with the selected issuer's pinned keys succeeds they are
// authenticated; they are never used as claims on their own.
type tokenPeek struct {
	issuer string
	jku    string
}

// trustedEntry peeks the unverified iss of raw and resolves it against the
// trust table.
func (c *Clearinghouse) trustedEntry(raw string) (issuerEntry, tokenPeek, error) {
	peek, err := peekToken(raw)
	if err != nil {
		return issuerEntry{}, tokenPeek{}, err
	}
	entry, ok := c.issuers[peek.issuer]
	if !ok {
		return issuerEntry{}, tokenPeek{}, fmt.Errorf("issuer %q is not trusted", peek.issuer)
	}

	return entry, peek, nil
}

// peekToken decodes the protected header and payload of a compact JWS without
// verifying anything.
func peekToken(raw string) (tokenPeek, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return tokenPeek{}, fmt.Errorf("token is not a compact JWS")
	}

	var header struct {
		JKU string `json:"jku"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return tokenPeek{}, fmt.Errorf("token header: %w", err)
	}

	var payload struct {
		Iss string `json:"iss"`
	}
	if err := decodeSegment(parts[1], &payload); err != nil {
		return tokenPeek{}, fmt.Errorf("token payload: %w", err)
	}

	return tokenPeek{issuer: payload.Iss, jku: header.JKU}, nil
}

func decodeSegment(seg string, dst any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return fmt.Errorf("not base64url: %w", err)
	}
	if err := json.Unmarshal(decoded, dst); err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}

	return nil
}
