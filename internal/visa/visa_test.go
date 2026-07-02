package visa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// refTime is a fixed clock reference so temporal tests do not depend on the wall
// clock. JWT timestamps carry second precision, so all test times are whole
// seconds.
var refTime = time.Unix(1_700_000_000, 0).UTC()

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	return key
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	return key
}

// verifierFor builds a Verifier trusting a single public key under kid.
func verifierFor(t *testing.T, kid string, pub crypto.PublicKey, opts ...VerifierOption) *Verifier {
	t.Helper()

	set, err := PublicJWKS(KeyEntry{KeyID: kid, Public: pub})
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}

	return NewVerifier(set, opts...)
}

// sampleClaims returns a well-formed Visa Document Token payload valid at refTime.
func sampleClaims() Claims {
	return Claims{
		Issuer:   "https://issuer.example.org",
		Subject:  "user-123",
		IssuedAt: refTime.Add(-time.Minute),
		Expires:  refTime.Add(time.Hour),
		Visa: Object{
			Type:     "ControlledAccessGrants",
			Asserted: refTime.Add(-24 * time.Hour).Unix(),
			Value:    "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001",
			Source:   "https://ddbj.nig.ac.jp/dac",
			By:       "dac",
		},
	}
}

func TestSignVerifyRoundTripRSA(t *testing.T) {
	key := rsaKey(t)
	signer, err := NewSigner(key, "rsa-1", "https://issuer.example.org/jwks")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	token, err := signer.Sign(sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := verifierFor(t, "rsa-1", key.Public(), WithClock(func() time.Time { return refTime })).Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	assertClaimsEqual(t, sampleClaims(), got)
}

func TestSignVerifyRoundTripES256(t *testing.T) {
	key := ecKey(t)
	signer, err := NewSigner(key, "ec-1", "")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	token, err := signer.Sign(sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := verifierFor(t, "ec-1", key.Public(), WithClock(func() time.Time { return refTime })).Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	assertClaimsEqual(t, sampleClaims(), got)
}

// TestRoundTripProperty checks that any well-formed claims survive a sign then
// verify unchanged, for both key families.
func TestRoundTripProperty(t *testing.T) {
	rsa := rsaKey(t)
	ec := ecKey(t)

	rapid.Check(t, func(rt *rapid.T) {
		useRSA := rapid.Bool().Draw(rt, "useRSA")
		var key crypto.Signer
		if useRSA {
			key = rsa
		} else {
			key = ec
		}

		now := time.Unix(rapid.Int64Range(1_600_000_000, 1_900_000_000).Draw(rt, "now"), 0).UTC()
		claims := Claims{
			Issuer:   "https://issuer.example.org/" + rapid.StringN(1, 20, 40).Draw(rt, "iss"),
			Subject:  rapid.StringN(1, 30, 60).Draw(rt, "sub"),
			IssuedAt: now.Add(-time.Duration(rapid.Int64Range(0, 3600).Draw(rt, "iatBack")) * time.Second),
			Expires:  now.Add(time.Duration(rapid.Int64Range(1, 86400).Draw(rt, "expFwd")) * time.Second),
			ID:       rapid.StringN(0, 20, 40).Draw(rt, "jti"),
			Visa: Object{
				Type:     rapid.SampledFrom([]string{"ControlledAccessGrants", "AffiliationAndRole", "ResearcherStatus"}).Draw(rt, "type"),
				Asserted: rapid.Int64Range(0, 4_102_444_800).Draw(rt, "asserted"),
				Value:    rapid.StringN(0, 40, 80).Draw(rt, "value"),
				Source:   rapid.StringN(0, 40, 80).Draw(rt, "source"),
				By:       rapid.SampledFrom([]string{"", "dac", "self", "so", "system"}).Draw(rt, "by"),
			},
		}

		signer, err := NewSigner(key, "k", "")
		if err != nil {
			rt.Fatalf("new signer: %v", err)
		}
		token, err := signer.Sign(claims)
		if err != nil {
			rt.Fatalf("sign: %v", err)
		}

		got, err := verifierFor(t, "k", key.Public(), WithClock(func() time.Time { return now })).Verify(token)
		if err != nil {
			rt.Fatalf("verify: %v", err)
		}
		assertClaimsEqual(rt, claims, got)
	})
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	key := ecKey(t)
	signer, _ := NewSigner(key, "ec-1", "")
	token, err := signer.Sign(sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parts := strings.Split(token, ".")
	parts[1] = mutateSegment(t, parts[1])
	tampered := strings.Join(parts, ".")

	if _, err := verifierFor(t, "ec-1", key.Public(), WithClock(func() time.Time { return refTime })).Verify(tampered); err == nil {
		t.Fatal("expected verify to reject a tampered payload, got nil")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	key := ecKey(t)
	signer, _ := NewSigner(key, "ec-1", "")
	token, err := signer.Sign(sampleClaims())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parts := strings.Split(token, ".")
	parts[2] = mutateSegment(t, parts[2])
	tampered := strings.Join(parts, ".")

	if _, err := verifierFor(t, "ec-1", key.Public(), WithClock(func() time.Time { return refTime })).Verify(tampered); err == nil {
		t.Fatal("expected verify to reject a tampered signature, got nil")
	}
}

// mutateSegment flips one base64url character of seg to a different one, changing
// the decoded bytes while keeping the segment decodable.
func mutateSegment(t *testing.T, seg string) string {
	t.Helper()

	if seg == "" {
		t.Fatal("cannot mutate an empty segment")
	}

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	mid := len(seg) / 2
	orig := seg[mid]
	repl := alphabet[0]
	if orig == repl {
		repl = alphabet[1]
	}

	return seg[:mid] + string(repl) + seg[mid+1:]
}

func TestVerifyRejectsNoneAlg(t *testing.T) {
	key := ecKey(t)
	token := craftUnsignedToken(t, "ec-1")

	_, err := verifierFor(t, "ec-1", key.Public(), WithClock(func() time.Time { return refTime })).Verify(token)
	if !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("verify error = %v, want ErrAlgorithmNotAllowed", err)
	}
}

// craftUnsignedToken builds an alg=none token with the standard visa claims and no
// signature, the shape an attacker would submit to bypass signing.
func craftUnsignedToken(t *testing.T, kid string) string {
	t.Helper()

	header := map[string]any{"alg": "none", "typ": tokenType, "kid": kid}
	payload := map[string]any{
		"iss":     "https://issuer.example.org",
		"sub":     "user-123",
		"iat":     refTime.Add(-time.Minute).Unix(),
		"exp":     refTime.Add(time.Hour).Unix(),
		claimVisa: map[string]any{"type": "ControlledAccessGrants", "value": "d", "source": "s", "by": "dac", "asserted": 1},
	}

	return encodeSegment(t, header) + "." + encodeSegment(t, payload) + "."
}

// base64Raw returns the raw-base64url encoding of s, for building malformed
// header segments in tests.
func base64Raw(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func encodeSegment(t *testing.T, v any) string {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal segment: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
}

// TestVerifyRejectsHMACAlgConfusion covers the classic attack: an attacker takes
// the RSA public key, signs an HS256 token treating the public key bytes as the
// HMAC secret, and reuses the real kid. The header allowlist rejects it before any
// key is consulted.
func TestVerifyRejectsHMACAlgConfusion(t *testing.T) {
	key := rsaKey(t)
	forged := craftHS256Token(t, "rsa-1", publicKeyBytes(t, key.Public()))

	_, err := verifierFor(t, "rsa-1", key.Public(), WithClock(func() time.Time { return refTime })).Verify(forged)
	if !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("verify error = %v, want ErrAlgorithmNotAllowed", err)
	}
}

// craftHS256Token builds an HS256-signed token over the standard visa claims,
// using secret as the HMAC key. The signature is valid HMAC, so only the header
// allowlist stands between it and acceptance.
func craftHS256Token(t *testing.T, kid string, secret []byte) string {
	t.Helper()

	header := map[string]any{"alg": "HS256", "typ": tokenType, "kid": kid}
	payload := map[string]any{
		"iss":     "https://issuer.example.org",
		"sub":     "user-123",
		"iat":     refTime.Add(-time.Minute).Unix(),
		"exp":     refTime.Add(time.Hour).Unix(),
		claimVisa: map[string]any{"type": "ControlledAccessGrants", "value": "d", "source": "s", "by": "dac", "asserted": 1},
	}

	signingInput := encodeSegment(t, header) + "." + encodeSegment(t, payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

// publicKeyBytes returns the PKIX DER encoding of pub, the material an
// alg-confusion attacker would reuse as an HMAC secret.
func publicKeyBytes(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	return der
}

func assertClaimsEqual(t rapid.TB, want, got Claims) {
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
	assertVisaEqual(t, want.Visa, got.Visa)
}

func assertVisaEqual(t rapid.TB, want, got Object) {
	t.Helper()

	if got.Type != want.Type || got.Asserted != want.Asserted || got.Value != want.Value || got.Source != want.Source || got.By != want.By {
		t.Errorf("visa Object = %+v, want %+v", got, want)
	}
	if !jsonEqual(want.Conditions, got.Conditions) {
		t.Errorf("Conditions = %s, want %s", got.Conditions, want.Conditions)
	}
}

// jsonEqual compares two JSON payloads for semantic equality, tolerating
// reformatting from the re-encoding done while decoding the visa claim.
func jsonEqual(a, b json.RawMessage) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}

	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}

	return reflect.DeepEqual(av, bv)
}
