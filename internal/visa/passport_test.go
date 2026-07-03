package visa

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"pgregory.net/rapid"
)

// samplePassportClaims returns a well-formed Passport payload valid at refTime,
// carrying one signed visa.
func samplePassportClaims(t *testing.T, key crypto.Signer, kid string) PassportClaims {
	t.Helper()

	visa, err := mustSigner(t, key, kid).Sign(sampleClaims())
	if err != nil {
		t.Fatalf("sign inner visa: %v", err)
	}

	return PassportClaims{
		Issuer:   "https://issuer.example.org",
		Subject:  "user-123",
		IssuedAt: refTime.Add(-time.Minute),
		Expires:  refTime.Add(time.Hour),
		ID:       "passport-1",
		Visas:    []string{visa},
	}
}

func assertPassportClaimsEqual(t rapid.TB, want, got PassportClaims) {
	t.Helper()

	if got.Issuer != want.Issuer {
		t.Errorf("Issuer = %q, want %q", got.Issuer, want.Issuer)
	}
	if got.Subject != want.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if !got.IssuedAt.Equal(want.IssuedAt) {
		t.Errorf("IssuedAt = %s, want %s", got.IssuedAt, want.IssuedAt)
	}
	if !got.Expires.Equal(want.Expires) {
		t.Errorf("Expires = %s, want %s", got.Expires, want.Expires)
	}
	if got.ID != want.ID {
		t.Errorf("ID = %q, want %q", got.ID, want.ID)
	}
	if !slices.Equal(got.Visas, want.Visas) {
		t.Errorf("Visas = %q, want %q", got.Visas, want.Visas)
	}
}

func TestPassportSignVerifyRoundTripRSA(t *testing.T) {
	key := rsaKey(t)
	claims := samplePassportClaims(t, key, "rsa-1")

	token, err := mustSigner(t, key, "rsa-1").SignPassport(claims)
	if err != nil {
		t.Fatalf("sign passport: %v", err)
	}

	got, err := verifierFor(t, "rsa-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
	if err != nil {
		t.Fatalf("verify passport: %v", err)
	}
	assertPassportClaimsEqual(t, claims, got)
}

func TestPassportSignVerifyRoundTripES256(t *testing.T) {
	key := ecKey(t)
	claims := samplePassportClaims(t, key, "ec-1")

	token, err := mustSigner(t, key, "ec-1").SignPassport(claims)
	if err != nil {
		t.Fatalf("sign passport: %v", err)
	}

	got, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
	if err != nil {
		t.Fatalf("verify passport: %v", err)
	}
	assertPassportClaimsEqual(t, claims, got)
}

// TestPassportRoundTripProperty checks that any well-formed passport survives a
// sign then verify unchanged, including empty visa arrays.
func TestPassportRoundTripProperty(t *testing.T) {
	rsa := rsaKey(t)
	ec := ecKey(t)

	rapid.Check(t, func(rt *rapid.T) {
		var key crypto.Signer = ec
		if rapid.Bool().Draw(rt, "useRSA") {
			key = rsa
		}

		now := time.Unix(rapid.Int64Range(1_600_000_000, 1_900_000_000).Draw(rt, "now"), 0).UTC()
		claims := PassportClaims{
			Issuer:   "https://issuer.example.org/" + rapid.StringN(1, 20, 40).Draw(rt, "iss"),
			Subject:  rapid.StringN(1, 30, 60).Draw(rt, "sub"),
			IssuedAt: now.Add(-time.Duration(rapid.Int64Range(0, 3600).Draw(rt, "iatBack")) * time.Second),
			Expires:  now.Add(time.Duration(rapid.Int64Range(1, 86400).Draw(rt, "expFwd")) * time.Second),
			ID:       rapid.StringN(0, 20, 40).Draw(rt, "jti"),
			Visas:    rapid.SliceOfN(rapid.StringN(0, 40, 80), 0, 4).Draw(rt, "visas"),
		}

		signer, err := NewSigner(key, "k", "")
		if err != nil {
			rt.Fatalf("new signer: %v", err)
		}
		token, err := signer.SignPassport(claims)
		if err != nil {
			rt.Fatalf("sign passport: %v", err)
		}

		got, err := verifierFor(t, "k", key.Public(), WithClock(func() time.Time { return now })).VerifyPassport(token)
		if err != nil {
			rt.Fatalf("verify passport: %v", err)
		}
		want := claims
		if want.Visas == nil {
			want.Visas = []string{}
		}
		assertPassportClaimsEqual(rt, want, got)
	})
}

// TestSignPassportNilVisasBecomesEmptyArray pins that a passport with no grants
// still carries the REQUIRED ga4gh_passport_v1 claim as an empty array.
func TestSignPassportNilVisasBecomesEmptyArray(t *testing.T) {
	key := ecKey(t)
	claims := samplePassportClaims(t, key, "ec-1")
	claims.Visas = nil

	token, err := mustSigner(t, key, "ec-1").SignPassport(claims)
	if err != nil {
		t.Fatalf("sign passport: %v", err)
	}

	got, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
	if err != nil {
		t.Fatalf("verify passport: %v", err)
	}
	if got.Visas == nil || len(got.Visas) != 0 {
		t.Fatalf("Visas = %#v, want empty non-nil slice", got.Visas)
	}
}

func TestSignPassportRejectsMissingStandardClaims(t *testing.T) {
	key := ecKey(t)
	base := samplePassportClaims(t, key, "ec-1")

	cases := []struct {
		name   string
		mutate func(*PassportClaims)
	}{
		{"missing iss", func(c *PassportClaims) { c.Issuer = "" }},
		{"missing sub", func(c *PassportClaims) { c.Subject = "" }},
		{"missing iat", func(c *PassportClaims) { c.IssuedAt = time.Time{} }},
		{"missing exp", func(c *PassportClaims) { c.Expires = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := base
			tc.mutate(&claims)
			if _, err := mustSigner(t, key, "ec-1").SignPassport(claims); !errors.Is(err, ErrMissingClaim) {
				t.Fatalf("error = %v, want ErrMissingClaim", err)
			}
		})
	}
}

// passportPayload returns the payload claims of a well-formed passport valid at
// refTime, as a mutable map so tests can deviate in exactly one dimension.
func passportPayload() map[string]any {
	return map[string]any{
		"iss":         "https://issuer.example.org",
		"sub":         "user-123",
		"iat":         refTime.Add(-time.Minute),
		"exp":         refTime.Add(time.Hour),
		claimPassport: []string{},
	}
}

// signShaped signs a token assembled from arbitrary protected headers and
// payload claims, so tests can craft tokens that SignPassport refuses to mint.
func signShaped(t *testing.T, key crypto.Signer, alg jwa.SignatureAlgorithm, headers, claims map[string]any) string {
	t.Helper()

	b := jwt.NewBuilder()
	for k, v := range claims {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	hdr := jws.NewHeaders()
	for k, v := range headers {
		if err := hdr.Set(k, v); err != nil {
			t.Fatalf("set header %s: %v", k, err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return string(signed)
}

// hmacToken builds an HS256-signed token over arbitrary header and payload maps,
// the shape an algorithm-confusion attacker submits with a public key as secret.
func hmacToken(t *testing.T, header, payload map[string]any, secret []byte) string {
	t.Helper()

	signingInput := encodeSegment(t, header) + "." + encodeSegment(t, payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

func TestVerifyPassportTypRequired(t *testing.T) {
	key := ecKey(t)

	cases := []struct {
		name    string
		headers map[string]any
	}{
		{"absent typ", map[string]any{"kid": "ec-1"}},
		{"visa typ", map[string]any{"kid": "ec-1", "typ": tokenType}},
		{"plain JWT typ", map[string]any{"kid": "ec-1", "typ": "JWT"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := signShaped(t, key, jwa.ES256(), tc.headers, passportPayload())
			_, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
			if !errors.Is(err, ErrUnexpectedTokenType) {
				t.Fatalf("error = %v, want ErrUnexpectedTokenType", err)
			}
		})
	}
}

// TestVerifyPassportTypComparisonRFC7515 pins the RFC 7515 §4.1.9 comparison:
// case-insensitive, with a bare subtype equivalent to application/<subtype>.
func TestVerifyPassportTypComparisonRFC7515(t *testing.T) {
	key := ecKey(t)

	for _, typ := range []string{"vnd.ga4gh.passport+jwt", "VND.GA4GH.Passport+JWT", "application/vnd.ga4gh.passport+jwt"} {
		t.Run(typ, func(t *testing.T) {
			token := signShaped(t, key, jwa.ES256(), map[string]any{"kid": "ec-1", "typ": typ}, passportPayload())
			if _, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).VerifyPassport(token); err != nil {
				t.Fatalf("verify passport with typ %q: %v", typ, err)
			}
		})
	}
}

func TestVerifyPassportRejectsNoneAlg(t *testing.T) {
	key := ecKey(t)

	header := map[string]any{"alg": "none", "typ": passportTokenType, "kid": "ec-1"}
	payload := map[string]any{
		"iss":         "https://issuer.example.org",
		"sub":         "user-123",
		"iat":         refTime.Add(-time.Minute).Unix(),
		"exp":         refTime.Add(time.Hour).Unix(),
		claimPassport: []string{},
	}
	token := encodeSegment(t, header) + "." + encodeSegment(t, payload) + "."

	_, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
	if !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("error = %v, want ErrAlgorithmNotAllowed", err)
	}
}

func TestVerifyPassportRejectsHMACAlgConfusion(t *testing.T) {
	key := rsaKey(t)

	header := map[string]any{"alg": "HS256", "typ": passportTokenType, "kid": "rsa-1"}
	payload := map[string]any{
		"iss":         "https://issuer.example.org",
		"sub":         "user-123",
		"iat":         refTime.Add(-time.Minute).Unix(),
		"exp":         refTime.Add(time.Hour).Unix(),
		claimPassport: []string{},
	}
	token := hmacToken(t, header, payload, publicKeyBytes(t, key.Public()))

	_, err := verifierFor(t, "rsa-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
	if !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("error = %v, want ErrAlgorithmNotAllowed", err)
	}
}

func TestVerifyPassportRejectsMissingPassportClaim(t *testing.T) {
	key := ecKey(t)

	payload := passportPayload()
	delete(payload, claimPassport)
	token := signShaped(t, key, jwa.ES256(), map[string]any{"kid": "ec-1", "typ": passportTokenType}, payload)

	_, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
	if !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("error = %v, want ErrMissingClaim", err)
	}
}

func TestVerifyPassportRejectsMalformedVisaArray(t *testing.T) {
	key := ecKey(t)

	cases := []struct {
		name  string
		value any
	}{
		{"non-string element", []any{123}},
		{"not an array", "visa"},
		{"null", json.RawMessage("null")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := passportPayload()
			payload[claimPassport] = tc.value
			token := signShaped(t, key, jwa.ES256(), map[string]any{"kid": "ec-1", "typ": passportTokenType}, payload)

			_, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
			if !errors.Is(err, ErrInvalidClaim) {
				t.Fatalf("error = %v, want ErrInvalidClaim", err)
			}
		})
	}
}

func TestVerifyPassportTemporalBoundaries(t *testing.T) {
	key := ecKey(t)
	claims := samplePassportClaims(t, key, "ec-1")

	token, err := mustSigner(t, key, "ec-1").SignPassport(claims)
	if err != nil {
		t.Fatalf("sign passport: %v", err)
	}

	// exp == now is expired: validity requires now strictly before exp.
	if _, err := verifierFor(t, "ec-1", key.Public(), clockAt(claims.Expires)).VerifyPassport(token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("at exp: error = %v, want ErrTokenExpired", err)
	}
	// One second before exp is still valid.
	if _, err := verifierFor(t, "ec-1", key.Public(), clockAt(claims.Expires.Add(-time.Second))).VerifyPassport(token); err != nil {
		t.Fatalf("just before exp: %v", err)
	}
	// iat in the future is rejected.
	if _, err := verifierFor(t, "ec-1", key.Public(), clockAt(claims.IssuedAt.Add(-time.Second))).VerifyPassport(token); !errors.Is(err, ErrTokenNotYetIssued) {
		t.Fatalf("before iat: error = %v, want ErrTokenNotYetIssued", err)
	}
}

// TestVerifyRejectsAudience pins that any token carrying an aud claim is
// rejected, on both the visa and passport paths: this verifier never checks
// audiences, so accepting one would violate RFC 8725 §3.9.
func TestVerifyRejectsAudience(t *testing.T) {
	key := ecKey(t)

	t.Run("passport", func(t *testing.T) {
		payload := passportPayload()
		payload["aud"] = []string{"https://other.example.org"}
		token := signShaped(t, key, jwa.ES256(), map[string]any{"kid": "ec-1", "typ": passportTokenType}, payload)

		_, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
		if !errors.Is(err, ErrAudiencePresent) {
			t.Fatalf("error = %v, want ErrAudiencePresent", err)
		}
	})

	t.Run("visa", func(t *testing.T) {
		token := signRaw(t, key, jwa.ES256(), "ec-1", func(b *jwt.Builder) *jwt.Builder {
			c := sampleClaims()
			return b.Issuer(c.Issuer).
				Subject(c.Subject).
				IssuedAt(c.IssuedAt).
				Expiration(c.Expires).
				Claim(claimVisa, c.Visa).
				Audience([]string{"https://other.example.org"})
		})

		_, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).Verify(token)
		if !errors.Is(err, ErrAudiencePresent) {
			t.Fatalf("error = %v, want ErrAudiencePresent", err)
		}
	})
}

// TestVerifyRejectsFutureNbf pins that a present nbf is honored even though the
// GA4GH profile does not use it: a token that says "not before" a future time
// must not be accepted early.
func TestVerifyRejectsFutureNbf(t *testing.T) {
	key := ecKey(t)

	build := func(nbf time.Time) string {
		return signRaw(t, key, jwa.ES256(), "ec-1", func(b *jwt.Builder) *jwt.Builder {
			c := sampleClaims()
			return b.Issuer(c.Issuer).
				Subject(c.Subject).
				IssuedAt(c.IssuedAt).
				Expiration(c.Expires).
				Claim(claimVisa, c.Visa).
				NotBefore(nbf)
		})
	}

	if _, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).Verify(build(refTime.Add(time.Minute))); !errors.Is(err, ErrTokenNotYetValid) {
		t.Fatalf("future nbf: error = %v, want ErrTokenNotYetValid", err)
	}
	if _, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).Verify(build(refTime.Add(-time.Minute))); err != nil {
		t.Fatalf("past nbf: %v", err)
	}
}

// TestVerifyRejectsCriticalHeader pins that a JWS with a crit header is rejected:
// no extensions are supported, and RFC 7515 §4.1.11 forbids accepting a token
// whose critical extensions are not understood.
func TestVerifyRejectsCriticalHeader(t *testing.T) {
	key := ecKey(t)
	headers := map[string]any{
		"kid":  "ec-1",
		"typ":  passportTokenType,
		"crit": []string{"b64"},
		"b64":  true,
	}
	token := signShaped(t, key, jwa.ES256(), headers, passportPayload())

	_, err := verifierFor(t, "ec-1", key.Public(), clockAt(refTime)).VerifyPassport(token)
	if !errors.Is(err, ErrCriticalHeader) {
		t.Fatalf("error = %v, want ErrCriticalHeader", err)
	}
}

// TestTokenKindConfusion pins that a visa cannot pass as a passport (typ check)
// and a passport cannot pass as a visa (missing ga4gh_visa_v1 claim).
func TestTokenKindConfusion(t *testing.T) {
	key := ecKey(t)
	signer := mustSigner(t, key, "ec-1")
	verifier := verifierFor(t, "ec-1", key.Public(), clockAt(refTime))

	visaToken, err := signer.Sign(sampleClaims())
	if err != nil {
		t.Fatalf("sign visa: %v", err)
	}
	if _, err := verifier.VerifyPassport(visaToken); !errors.Is(err, ErrUnexpectedTokenType) {
		t.Fatalf("visa as passport: error = %v, want ErrUnexpectedTokenType", err)
	}

	passportToken, err := signer.SignPassport(samplePassportClaims(t, key, "ec-1"))
	if err != nil {
		t.Fatalf("sign passport: %v", err)
	}
	if _, err := verifier.Verify(passportToken); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("passport as visa: error = %v, want ErrMissingClaim", err)
	}
}
