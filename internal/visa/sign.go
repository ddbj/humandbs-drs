package visa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Signer mints Visa Document Tokens with a fixed private key, key ID, and, when
// set, a JWKS URL advertised as the token's `jku` header.
type Signer struct {
	alg jwa.SignatureAlgorithm
	key crypto.PrivateKey
	kid string
	jku string
}

// NewSigner builds a Signer over key. The algorithm follows the key type: RSA
// signs with RS256 and ECDSA over P-256 signs with ES256; any other key is
// rejected. kid is required so a verifier can select this key from a JWKS. jku is
// optional and, when non-empty, is set as the `jku` header pointing at the
// issuer's JWKS URL.
func NewSigner(key crypto.PrivateKey, kid, jku string) (*Signer, error) {
	if kid == "" {
		return nil, fmt.Errorf("visa: signer requires a kid")
	}

	alg, err := signatureAlgForPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &Signer{alg: alg, key: key, kid: kid, jku: jku}, nil
}

// Sign builds and signs a Visa Document Token for c. It fails if any required
// standard claim (iss, sub, iat, exp) is absent, so an incomplete visa is never
// minted.
func (s *Signer) Sign(c Claims) (string, error) {
	if err := requireStandardClaims(c.Issuer, c.Subject, c.IssuedAt, c.Expires); err != nil {
		return "", err
	}

	b := jwt.NewBuilder().
		Issuer(c.Issuer).
		Subject(c.Subject).
		IssuedAt(c.IssuedAt).
		Expiration(c.Expires).
		Claim(claimVisa, c.Visa)
	if c.ID != "" {
		b = b.JwtID(c.ID)
	}

	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("visa: build token: %w", err)
	}

	return s.signToken(tok, tokenType)
}

// signToken signs tok with the Signer's key under the given `typ` header,
// attaching the kid and, when configured, the jku. Visas and passports share
// this so the header discipline cannot diverge between the two token kinds.
func (s *Signer) signToken(tok jwt.Token, typ string) (string, error) {
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.TypeKey, typ); err != nil {
		return "", fmt.Errorf("visa: set typ header: %w", err)
	}
	if err := hdr.Set(jws.KeyIDKey, s.kid); err != nil {
		return "", fmt.Errorf("visa: set kid header: %w", err)
	}
	if s.jku != "" {
		if err := hdr.Set(jws.JWKSetURLKey, s.jku); err != nil {
			return "", fmt.Errorf("visa: set jku header: %w", err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(s.alg, s.key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", fmt.Errorf("visa: sign token: %w", err)
	}

	return string(signed), nil
}

// requireStandardClaims reports the standard claims the specification marks
// REQUIRED on both visas and passports but that are absent.
func requireStandardClaims(iss, sub string, iat, exp time.Time) error {
	var missing []string
	if iss == "" {
		missing = append(missing, "iss")
	}
	if sub == "" {
		missing = append(missing, "sub")
	}
	if iat.IsZero() {
		missing = append(missing, "iat")
	}
	if exp.IsZero() {
		missing = append(missing, "exp")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingClaim, strings.Join(missing, ", "))
	}

	return nil
}

// signatureAlgForPrivateKey maps a private key to its GA4GH signing algorithm.
func signatureAlgForPrivateKey(key crypto.PrivateKey) (jwa.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return jwa.RS256(), nil
	case *ecdsa.PrivateKey:
		return ecdsaAlg(k.Curve)
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("%w: %T", ErrUnsupportedKey, key)
	}
}

// ecdsaAlg maps an ECDSA curve to ES256, the only conformant EC algorithm, and
// rejects any curve other than P-256.
func ecdsaAlg(curve elliptic.Curve) (jwa.SignatureAlgorithm, error) {
	if curve != elliptic.P256() {
		return jwa.SignatureAlgorithm{}, fmt.Errorf("%w: ECDSA curve %s, only P-256 (ES256) is supported", ErrUnsupportedKey, curve.Params().Name)
	}

	return jwa.ES256(), nil
}
