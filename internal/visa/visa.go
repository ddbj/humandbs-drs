// Package visa implements GA4GH Visa Document Tokens: the assembly, signing,
// parsing, and verification of the self-contained JWTs that a Visa Issuer mints
// and a Passport Clearinghouse validates. It is shared by cmd/issuer and the DRS
// Clearinghouse (architecture.md § "Issuer 設計", § "Clearinghouse 設計").
//
// A Visa Document Token carries the ga4gh_visa_v1 claim (a Visa Object) alongside
// the standard iss/sub/iat/exp claims, signed with RS256 or ES256. Only those two
// algorithms are accepted; unsigned ("none") and HMAC ("HS256") tokens are rejected
// to block algorithm-confusion attacks (AAI profile § Signing Algorithms).
package visa

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

// claimVisa is the JWT private claim name that carries the Visa Object.
const claimVisa = "ga4gh_visa_v1"

// tokenType is the recommended `typ` header value for Visa Document Tokens.
const tokenType = "vnd.ga4gh.visa+jwt"

// TypeControlledAccessGrants is the Visa Object `type` asserting that a DAC
// granted the subject access to the dataset named by `value`
// (ga4gh_passport_v1 § Visa Types). The issuer mints visas of this type and the
// Clearinghouse requires it when authorizing controlled data.
const TypeControlledAccessGrants = "ControlledAccessGrants"

// Errors reported by signing and verification. Callers match these with
// errors.Is to distinguish an untrusted algorithm or a malformed token from a
// signature or key failure.
var (
	// ErrAlgorithmNotAllowed reports a token signed with an algorithm outside the
	// RS256/ES256 allowlist, including "none" and any HMAC variant.
	ErrAlgorithmNotAllowed = errors.New("visa: signing algorithm not allowed")
	// ErrMalformedToken reports a token that is not a well-formed compact JWS.
	ErrMalformedToken = errors.New("visa: malformed token")
	// ErrMissingClaim reports an absent required claim (iss, sub, iat, exp, or the
	// ga4gh_visa_v1 Visa Object).
	ErrMissingClaim = errors.New("visa: missing required claim")
	// ErrTokenExpired reports a token whose exp is at or before the current time.
	ErrTokenExpired = errors.New("visa: token expired")
	// ErrTokenNotYetIssued reports a token whose iat is in the future.
	ErrTokenNotYetIssued = errors.New("visa: token issued in the future")
	// ErrUnsupportedKey reports a key that is neither RSA nor ECDSA P-256.
	ErrUnsupportedKey = errors.New("visa: unsupported key type")
)

// Object is the value of the ga4gh_visa_v1 claim, a GA4GH Visa Object
// (ga4gh_passport_v1 § Visa Format). Conditions is carried verbatim so a token
// that restricts its validity round-trips without loss; evaluating it is the
// Clearinghouse's responsibility (architecture.md § "Clearinghouse 設計").
type Object struct {
	Type       string          `json:"type"`
	Asserted   int64           `json:"asserted"`
	Value      string          `json:"value"`
	Source     string          `json:"source"`
	By         string          `json:"by,omitempty"`
	Conditions json.RawMessage `json:"conditions,omitempty"`
}

// Claims is the decoded payload of a Visa Document Token: the standard JWT claims
// the specification requires (iss/sub/iat/exp), the optional jti, and the Visa
// Object.
type Claims struct {
	Issuer   string
	Subject  string
	IssuedAt time.Time
	Expires  time.Time
	ID       string
	Visa     Object
}

// allowedAlg reports whether name is a conformant GA4GH signing algorithm. The
// AAI profile permits only ES256 and RS256; restricting to these rejects "none"
// and HMAC algorithms that would otherwise enable algorithm confusion.
func allowedAlg(name string) bool {
	switch name {
	case jwa.RS256().String(), jwa.ES256().String():
		return true
	default:
		return false
	}
}
