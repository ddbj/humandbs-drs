package visa

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// claimPassport is the JWT claim name that carries the array of Visa JWTs
// (ga4gh_passport_v1 § Passport Claim Format).
const claimPassport = "ga4gh_passport_v1"

// passportTokenType is the REQUIRED `typ` header value for Passports
// (AAI profile § Passport Format).
const passportTokenType = "vnd.ga4gh.passport+jwt"

// PassportClaims is the decoded payload of a Passport: the standard JWT claims
// the specification requires (iss/sub/iat/exp), the optional jti, and the
// embedded Visa JWTs. Each Visa is carried as its compact serialization and
// must be verified separately; verifying the Passport only vouches for the
// envelope.
type PassportClaims struct {
	Issuer   string
	Subject  string
	IssuedAt time.Time
	Expires  time.Time
	ID       string
	Visas    []string
}

// SignPassport builds and signs a Passport for c. It fails if any required
// standard claim (iss, sub, iat, exp) is absent. A nil Visas is minted as an
// empty array, because ga4gh_passport_v1 is REQUIRED even when the user holds
// no visas.
func (s *Signer) SignPassport(c PassportClaims) (string, error) {
	if err := requireStandardClaims(c.Issuer, c.Subject, c.IssuedAt, c.Expires); err != nil {
		return "", err
	}

	visas := c.Visas
	if visas == nil {
		visas = []string{}
	}

	b := jwt.NewBuilder().
		Issuer(c.Issuer).
		Subject(c.Subject).
		IssuedAt(c.IssuedAt).
		Expiration(c.Expires).
		Claim(claimPassport, visas)
	if c.ID != "" {
		b = b.JwtID(c.ID)
	}

	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("visa: build passport: %w", err)
	}

	return s.signToken(tok, passportTokenType)
}

// VerifyPassport checks a Passport and returns its claims. On top of the checks
// shared with Verify (algorithm allowlist, crit rejection, signature by `kid`,
// no `aud`, temporal claims), it requires the `typ` header to name the passport
// media type and the ga4gh_passport_v1 claim to be an array of strings.
func (v *Verifier) VerifyPassport(raw string) (PassportClaims, error) {
	tok, err := v.parseVerified(raw, passportTokenType)
	if err != nil {
		return PassportClaims{}, err
	}

	claims, err := passportClaimsFromToken(tok)
	if err != nil {
		return PassportClaims{}, err
	}
	if err := v.checkTemporal(tok, claims.IssuedAt, claims.Expires); err != nil {
		return PassportClaims{}, err
	}

	return claims, nil
}

// passportClaimsFromToken extracts the required standard claims and the visa
// array, reporting an absent claim or a claim of the wrong shape.
func passportClaimsFromToken(tok jwt.Token) (PassportClaims, error) {
	iss, sub, iat, exp, err := standardClaimsFromToken(tok)
	if err != nil {
		return PassportClaims{}, err
	}

	visas, err := visasFromToken(tok)
	if err != nil {
		return PassportClaims{}, err
	}

	jti, _ := tok.JwtID()

	return PassportClaims{Issuer: iss, Subject: sub, IssuedAt: iat, Expires: exp, ID: jti, Visas: visas}, nil
}

// visasFromToken decodes the ga4gh_passport_v1 claim, requiring an array of
// strings (empty allowed). Anything else — null, a non-array, or non-string
// elements — is rejected rather than coerced, so a malformed passport cannot
// smuggle values past the shape check.
func visasFromToken(tok jwt.Token) ([]string, error) {
	if !tok.Has(claimPassport) {
		return nil, fmt.Errorf("%w: %s", ErrMissingClaim, claimPassport)
	}

	var raw any
	if err := tok.Get(claimPassport, &raw); err != nil {
		// A claim jwx cannot even hand back as `any` (such as a JSON null) has
		// no usable shape.
		return nil, fmt.Errorf("%w: read %s claim: %w", ErrInvalidClaim, claimPassport, err)
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("visa: re-encode %s claim: %w", claimPassport, err)
	}
	if string(encoded) == "null" {
		return nil, fmt.Errorf("%w: %s is null", ErrInvalidClaim, claimPassport)
	}

	var visas []string
	if err := json.Unmarshal(encoded, &visas); err != nil {
		return nil, fmt.Errorf("%w: %s must be an array of strings", ErrInvalidClaim, claimPassport)
	}
	if visas == nil {
		visas = []string{}
	}

	return visas, nil
}
