package visa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// clockAt returns a VerifierOption pinning the clock to at.
func clockAt(at time.Time) VerifierOption {
	return WithClock(func() time.Time { return at })
}

// signRaw signs an arbitrary token with key under kid, so tests can produce
// validly signed tokens that omit required claims. build customizes the payload.
func signRaw(t *testing.T, key crypto.Signer, alg jwa.SignatureAlgorithm, kid string, build func(*jwt.Builder) *jwt.Builder) string {
	t.Helper()

	tok, err := build(jwt.NewBuilder()).Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return string(signed)
}

func signValid(t *testing.T, key crypto.Signer, kid string, c Claims) string {
	t.Helper()

	token, err := mustSigner(t, key, kid).Sign(c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return token
}

func TestVerifyExpiryBoundary(t *testing.T) {
	key := ecKey(t)
	claims := sampleClaims()
	claims.IssuedAt = refTime.Add(-time.Hour)
	claims.Expires = refTime
	token := signValid(t, key, "ec-1", claims)

	cases := []struct {
		name    string
		now     time.Time
		expired bool
	}{
		{"one second before exp", refTime.Add(-time.Second), false},
		{"exactly at exp", refTime, true},
		{"one second after exp", refTime.Add(time.Second), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifierFor(t, "ec-1", key.Public(), clockAt(tc.now)).Verify(token)
			if tc.expired {
				if !errors.Is(err, ErrTokenExpired) {
					t.Fatalf("error = %v, want ErrTokenExpired", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyFutureIatBoundary(t *testing.T) {
	key := ecKey(t)
	claims := sampleClaims()
	claims.IssuedAt = refTime
	claims.Expires = refTime.Add(time.Hour)
	token := signValid(t, key, "ec-1", claims)

	cases := []struct {
		name   string
		now    time.Time
		future bool
	}{
		{"iat in the future", refTime.Add(-time.Second), true},
		{"iat equals now", refTime, false},
		{"iat in the past", refTime.Add(time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifierFor(t, "ec-1", key.Public(), clockAt(tc.now)).Verify(token)
			if tc.future {
				if !errors.Is(err, ErrTokenNotYetIssued) {
					t.Fatalf("error = %v, want ErrTokenNotYetIssued", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyLeewayAbsorbsSkew(t *testing.T) {
	key := ecKey(t)

	expired := sampleClaims()
	expired.IssuedAt = refTime.Add(-time.Hour)
	expired.Expires = refTime
	expiredToken := signValid(t, key, "ec-1", expired)

	// 30s past exp, but a 60s leeway keeps it valid.
	if _, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime.Add(30*time.Second)), WithLeeway(60*time.Second)).Verify(expiredToken); err != nil {
		t.Fatalf("leeway should absorb 30s past exp: %v", err)
	}

	future := sampleClaims()
	future.IssuedAt = refTime.Add(30 * time.Second)
	future.Expires = refTime.Add(time.Hour)
	futureToken := signValid(t, key, "ec-1", future)

	// iat 30s ahead, but a 60s leeway keeps it valid.
	if _, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime), WithLeeway(60*time.Second)).Verify(futureToken); err != nil {
		t.Fatalf("leeway should absorb 30s future iat: %v", err)
	}
}

func TestVerifyRejectsUnknownKid(t *testing.T) {
	signKey := ecKey(t)
	token := signValid(t, signKey, "signing-kid", sampleClaims())

	// The verifier trusts a different key under a different kid.
	trusted := ecKey(t)
	set, err := PublicJWKS(KeyEntry{KeyID: "trusted-kid", Public: trusted.Public()})
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}

	_, err = NewVerifier(set, clockAt(refTime)).Verify(token)
	if err == nil {
		t.Fatal("expected verify to reject a token whose kid is not trusted, got nil")
	}
	if errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("error = %v, want a key-resolution failure, not an algorithm rejection", err)
	}
}

func TestVerifyRejectsMissingRequiredClaims(t *testing.T) {
	key := ecKey(t)
	alg := jwa.ES256()
	visa := map[string]any{"type": "ControlledAccessGrants", "value": "d", "source": "s", "by": "dac", "asserted": 1}

	cases := []struct {
		name  string
		build func(*jwt.Builder) *jwt.Builder
	}{
		{"missing exp", func(b *jwt.Builder) *jwt.Builder {
			return b.Issuer("iss").Subject("sub").IssuedAt(refTime).Claim(claimVisa, visa)
		}},
		{"missing iss", func(b *jwt.Builder) *jwt.Builder {
			return b.Subject("sub").IssuedAt(refTime).Expiration(refTime.Add(time.Hour)).Claim(claimVisa, visa)
		}},
		{"missing visa claim", func(b *jwt.Builder) *jwt.Builder {
			return b.Issuer("iss").Subject("sub").IssuedAt(refTime).Expiration(refTime.Add(time.Hour))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := signRaw(t, key, alg, "ec-1", tc.build)
			_, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).Verify(token)
			if !errors.Is(err, ErrMissingClaim) {
				t.Fatalf("error = %v, want ErrMissingClaim", err)
			}
		})
	}
}

func TestSignRejectsMissingStandardClaims(t *testing.T) {
	key := ecKey(t)
	signer, err := NewSigner(key, "ec-1", "")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	_, err = signer.Sign(Claims{Visa: Object{Type: "ControlledAccessGrants"}})
	if !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("error = %v, want ErrMissingClaim", err)
	}
	for _, want := range []string{"iss", "sub", "iat", "exp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention missing %q", err.Error(), want)
		}
	}
}

func TestNewSignerRejectsUnsupportedKeys(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}

	cases := []struct {
		name string
		key  crypto.PrivateKey
	}{
		{"ed25519", ed},
		{"ecdsa P-384", p384},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSigner(tc.key, "k", ""); !errors.Is(err, ErrUnsupportedKey) {
				t.Fatalf("error = %v, want ErrUnsupportedKey", err)
			}
		})
	}
}

func TestNewSignerRejectsEmptyKid(t *testing.T) {
	if _, err := NewSigner(ecKey(t), "", ""); err == nil {
		t.Fatal("expected NewSigner to reject an empty kid, got nil")
	}
}

func TestConditionsRoundTrip(t *testing.T) {
	key := ecKey(t)
	claims := sampleClaims()
	claims.Visa.Conditions = json.RawMessage(`[[{"type":"AffiliationAndRole","value":"const:faculty@example.org"}]]`)

	token, err := mustSigner(t, key, "ec-1").Sign(claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !jsonEqual(claims.Visa.Conditions, got.Visa.Conditions) {
		t.Fatalf("conditions = %s, want %s", got.Visa.Conditions, claims.Visa.Conditions)
	}
}

func mustSigner(t *testing.T, key crypto.Signer, kid string) *Signer {
	t.Helper()

	signer, err := NewSigner(key, kid, "")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	return signer
}

func TestAllowedAlg(t *testing.T) {
	allowed := []string{"RS256", "ES256"}
	rejected := []string{"none", "HS256", "RS384", "PS256", "ES384", "EdDSA", ""}

	for _, alg := range allowed {
		if !allowedAlg(alg) {
			t.Errorf("allowedAlg(%q) = false, want true", alg)
		}
	}
	for _, alg := range rejected {
		if allowedAlg(alg) {
			t.Errorf("allowedAlg(%q) = true, want false", alg)
		}
	}
}

func TestProtectedHeaderRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"no dot", "onlyonesegment"},
		{"empty header segment", ".payload.sig"},
		{"header not base64url", "!!!.payload.sig"},
		{"header not JSON", base64Raw("not json") + ".payload.sig"},
		{"header without alg", base64Raw(`{"typ":"JWT"}`) + ".payload.sig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protectedHeader(tc.raw); !errors.Is(err, ErrMalformedToken) {
				t.Fatalf("error = %v, want ErrMalformedToken", err)
			}
		})
	}
}
