package issuer

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

const (
	testIssuerURL = "https://issuer.example.org"
	testJKU       = testIssuerURL + "/jwks"
	testTTL       = time.Hour
)

// newPassportKit returns a PassportIssuer over a fresh RSA key and a Verifier
// that trusts that key, both pinned to the given clock.
func newPassportKit(t *testing.T, now func() time.Time) (*PassportIssuer, *visa.Verifier) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	signer, err := visa.NewSigner(key, kid, testJKU)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	issuer, err := NewPassportIssuer(signer, testIssuerURL, testTTL, WithPassportClock(now))
	if err != nil {
		t.Fatalf("NewPassportIssuer: %v", err)
	}

	keys, err := visa.PublicJWKS(visa.KeyEntry{KeyID: kid, Public: &key.PublicKey})
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}

	return issuer, visa.NewVerifier(keys, visa.WithClock(now))
}

// mintPassport mints a passport for subject and verifies its envelope,
// returning the decoded claims so tests can inspect the embedded visas.
func mintPassport(t *testing.T, p *PassportIssuer, verifier *visa.Verifier, subject string, grants []Grant) visa.PassportClaims {
	t.Helper()

	token, err := p.Passport(subject, grants)
	if err != nil {
		t.Fatalf("Passport: %v", err)
	}
	pc, err := verifier.VerifyPassport(token)
	if err != nil {
		t.Fatalf("VerifyPassport: %v", err)
	}

	return pc
}

func TestPassportMintsVerifiableVisa(t *testing.T) {
	p, verifier := newPassportKit(t, fixedClock(refTime))
	grant := sampleGrant()

	pc := mintPassport(t, p, verifier, grant.Subject, []Grant{grant})
	if pc.Issuer != testIssuerURL {
		t.Errorf("passport iss = %q, want %q", pc.Issuer, testIssuerURL)
	}
	if pc.Subject != grant.Subject {
		t.Errorf("passport sub = %q, want %q", pc.Subject, grant.Subject)
	}
	if !pc.IssuedAt.Equal(refTime) {
		t.Errorf("passport iat = %s, want %s", pc.IssuedAt, refTime)
	}
	if want := refTime.Add(testTTL); !pc.Expires.Equal(want) {
		t.Errorf("passport exp = %s, want %s", pc.Expires, want)
	}
	if pc.ID == "" {
		t.Error("passport jti is empty, want a unique token ID")
	}
	if len(pc.Visas) != 1 {
		t.Fatalf("len(visas) = %d, want 1", len(pc.Visas))
	}

	claims, err := verifier.Verify(pc.Visas[0])
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Issuer != testIssuerURL {
		t.Errorf("iss = %q, want %q", claims.Issuer, testIssuerURL)
	}
	if claims.Subject != grant.Subject {
		t.Errorf("sub = %q, want %q", claims.Subject, grant.Subject)
	}
	if !claims.IssuedAt.Equal(refTime) {
		t.Errorf("iat = %s, want %s", claims.IssuedAt, refTime)
	}
	// The grant expires well after now+TTL, so the TTL caps the visa.
	if want := refTime.Add(testTTL); !claims.Expires.Equal(want) {
		t.Errorf("exp = %s, want %s", claims.Expires, want)
	}
	if claims.ID == "" {
		t.Error("jti is empty, want a unique token ID")
	}
	if claims.Visa.Type != visa.TypeControlledAccessGrants {
		t.Errorf("visa type = %q, want %q", claims.Visa.Type, visa.TypeControlledAccessGrants)
	}
	if claims.Visa.Value != grant.DatasetID {
		t.Errorf("visa value = %q, want %q", claims.Visa.Value, grant.DatasetID)
	}
	if claims.Visa.Source != grant.DACSource {
		t.Errorf("visa source = %q, want %q", claims.Visa.Source, grant.DACSource)
	}
	if claims.Visa.By != "dac" {
		t.Errorf("visa by = %q, want %q", claims.Visa.By, "dac")
	}
	if claims.Visa.Asserted != grant.Asserted.Unix() {
		t.Errorf("visa asserted = %d, want %d", claims.Visa.Asserted, grant.Asserted.Unix())
	}
	if !bytes.Equal(claims.Visa.Conditions, grant.Conditions) {
		t.Errorf("visa conditions = %s, want %s", claims.Visa.Conditions, grant.Conditions)
	}
}

func TestPassportExpiryCappedByTTL(t *testing.T) {
	ttlCap := refTime.Add(testTTL)
	tests := []struct {
		name    string
		expires *time.Time
		want    time.Time
	}{
		{"no expiry uses ttl cap", nil, ttlCap},
		{"earlier grant expiry wins", timePtr(refTime.Add(30 * time.Minute)), refTime.Add(30 * time.Minute)},
		{"later grant expiry is capped", timePtr(refTime.Add(2 * time.Hour)), ttlCap},
		{"expiry equal to cap", timePtr(ttlCap), ttlCap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, verifier := newPassportKit(t, fixedClock(refTime))
			grant := sampleGrant()
			grant.Expires = tt.expires

			pc := mintPassport(t, p, verifier, grant.Subject, []Grant{grant})
			claims, err := verifier.Verify(pc.Visas[0])
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !claims.Expires.Equal(tt.want) {
				t.Errorf("exp = %s, want %s", claims.Expires, tt.want)
			}
		})
	}
}

func TestPassportEmptyGrantsMintsEmptyVisaArray(t *testing.T) {
	p, verifier := newPassportKit(t, fixedClock(refTime))

	pc := mintPassport(t, p, verifier, "user-123", nil)
	if len(pc.Visas) != 0 {
		t.Errorf("visas = %#v, want empty", pc.Visas)
	}
}

func TestPassportOmitsAbsentConditions(t *testing.T) {
	p, verifier := newPassportKit(t, fixedClock(refTime))
	grant := sampleGrant()
	grant.Conditions = nil

	pc := mintPassport(t, p, verifier, grant.Subject, []Grant{grant})
	claims, err := verifier.Verify(pc.Visas[0])
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Visa.Conditions != nil {
		t.Errorf("conditions = %s, want none", claims.Visa.Conditions)
	}
}

func TestPassportRejectsEmptySubject(t *testing.T) {
	p, _ := newPassportKit(t, fixedClock(refTime))

	if _, err := p.Passport("", []Grant{sampleGrant()}); err == nil {
		t.Fatal("want error for empty subject, got nil")
	}
}

func TestNewPassportIssuerValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := visa.NewSigner(key, "kid", testJKU)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	tests := []struct {
		name   string
		signer *visa.Signer
		issuer string
		ttl    time.Duration
	}{
		{"nil signer", nil, testIssuerURL, testTTL},
		{"empty issuer url", signer, "", testTTL},
		{"zero ttl", signer, testIssuerURL, 0},
		{"negative ttl", signer, testIssuerURL, -time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewPassportIssuer(tt.signer, tt.issuer, tt.ttl); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}
