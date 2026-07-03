package clearinghouse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

// refTime is a fixed clock reference so temporal tests do not depend on the
// wall clock.
var refTime = time.Unix(1_700_000_000, 0).UTC()

const (
	testDataset = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001"
	testDAC     = "https://ddbj.nig.ac.jp/dac"
	testSubject = "user-123"
)

var jtiCounter atomic.Int64

func nextJTI() string {
	return fmt.Sprintf("jti-%d", jtiCounter.Add(1))
}

// issuerKit is a signing issuer for tests: a fresh key pinned under a kid,
// plus signers for well-formed and deliberately deviant tokens.
type issuerKit struct {
	url     string
	jwksURL string
	kid     string
	key     *ecdsa.PrivateKey
	signer  *visa.Signer
	trusted Issuer
}

func newIssuerKit(t *testing.T, url string) *issuerKit {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksURL := url + "/jwks"
	const kid = "key-1"
	signer, err := visa.NewSigner(key, kid, jwksURL)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	keys, err := visa.PublicJWKS(visa.KeyEntry{KeyID: kid, Public: key.Public()})
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}

	return &issuerKit{
		url:     url,
		jwksURL: jwksURL,
		kid:     kid,
		key:     key,
		signer:  signer,
		trusted: Issuer{URL: url, JWKSURL: jwksURL, Keys: keys},
	}
}

// signerWithJKU returns a signer over the kit's key advertising jku, for
// crafting tokens whose jku deviates from the pinned JWKS URL.
func (k *issuerKit) signerWithJKU(t *testing.T, jku string) *visa.Signer {
	t.Helper()

	s, err := visa.NewSigner(k.key, k.kid, jku)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	return s
}

// grantClaims returns a well-formed ControlledAccessGrants visa payload for
// testDataset, valid at refTime.
func (k *issuerKit) grantClaims() visa.Claims {
	return visa.Claims{
		Issuer:   k.url,
		Subject:  testSubject,
		IssuedAt: refTime.Add(-time.Minute),
		Expires:  refTime.Add(time.Hour),
		ID:       nextJTI(),
		Visa: visa.Object{
			Type:     visa.TypeControlledAccessGrants,
			Asserted: refTime.Add(-24 * time.Hour).Unix(),
			Value:    testDataset,
			Source:   testDAC,
			By:       "dac",
		},
	}
}

// grantVisa signs a grant visa after applying mutate to the well-formed
// payload.
func (k *issuerKit) grantVisa(t *testing.T, mutate func(*visa.Claims)) string {
	t.Helper()

	c := k.grantClaims()
	if mutate != nil {
		mutate(&c)
	}
	signed, err := k.signer.Sign(c)
	if err != nil {
		t.Fatalf("sign visa: %v", err)
	}

	return signed
}

// passport signs a passport for testSubject embedding visas, applying mutate
// first.
func (k *issuerKit) passport(t *testing.T, visas []string, mutate func(*visa.PassportClaims)) string {
	t.Helper()

	c := visa.PassportClaims{
		Issuer:   k.url,
		Subject:  testSubject,
		IssuedAt: refTime.Add(-time.Minute),
		Expires:  refTime.Add(time.Hour),
		ID:       nextJTI(),
		Visas:    visas,
	}
	if mutate != nil {
		mutate(&c)
	}
	signed, err := k.signer.SignPassport(c)
	if err != nil {
		t.Fatalf("sign passport: %v", err)
	}

	return signed
}

// newClearinghouse builds a Clearinghouse trusting the kits, pinned to
// refTime.
func newClearinghouse(t *testing.T, kits ...*issuerKit) *Clearinghouse {
	t.Helper()

	issuers := make([]Issuer, 0, len(kits))
	for _, k := range kits {
		issuers = append(issuers, k.trusted)
	}
	c, err := New(issuers, WithClock(func() time.Time { return refTime }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return c
}

func TestNewValidation(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")

	cases := []struct {
		name    string
		issuers []Issuer
	}{
		{"no issuers", nil},
		{"empty issuer URL", []Issuer{{URL: "", JWKSURL: kit.jwksURL, Keys: kit.trusted.Keys}}},
		{"empty JWKS URL", []Issuer{{URL: kit.url, JWKSURL: "", Keys: kit.trusted.Keys}}},
		{"nil keys", []Issuer{{URL: kit.url, JWKSURL: kit.jwksURL, Keys: nil}}},
		{"duplicate issuer", []Issuer{kit.trusted, kit.trusted}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.issuers); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestAuthorizeGrantsValidPassport(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	ch := newClearinghouse(t, kit)

	var jti string
	passport := kit.passport(t, []string{kit.grantVisa(t, func(c *visa.Claims) { jti = c.ID })}, nil)

	grant, err := ch.Authorize(t.Context(), []string{passport}, testDataset)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	want := Grant{Subject: testSubject, Issuer: kit.url, JTI: jti}
	if grant != want {
		t.Errorf("grant = %+v, want %+v", grant, want)
	}
}

// TestAuthorizeByValues pins the accepted `by` values: organizational
// assertions grant, personal ones and an absent by do not.
func TestAuthorizeByValues(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	ch := newClearinghouse(t, kit)

	for by, want := range map[string]bool{"dac": true, "so": true, "system": true, "self": false, "peer": false, "": false} {
		t.Run("by="+by, func(t *testing.T) {
			passport := kit.passport(t, []string{kit.grantVisa(t, func(c *visa.Claims) { c.Visa.By = by })}, nil)
			_, err := ch.Authorize(t.Context(), []string{passport}, testDataset)
			if want && err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			if !want && !errors.Is(err, ErrNotAuthorized) {
				t.Fatalf("error = %v, want ErrNotAuthorized", err)
			}
		})
	}
}

func TestAuthorizeRequiresPassports(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	ch := newClearinghouse(t, kit)

	for name, passports := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			if _, err := ch.Authorize(t.Context(), passports, testDataset); !errors.Is(err, ErrNoValidPassport) {
				t.Fatalf("error = %v, want ErrNoValidPassport", err)
			}
		})
	}
}

func TestAuthorizeCapsPassportCount(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	ch := newClearinghouse(t, kit)

	passports := make([]string, maxPassports+1)
	for i := range passports {
		passports[i] = kit.passport(t, []string{kit.grantVisa(t, nil)}, nil)
	}

	if _, err := ch.Authorize(t.Context(), passports, testDataset); !errors.Is(err, ErrNoValidPassport) {
		t.Fatalf("error = %v, want ErrNoValidPassport", err)
	}
}

func TestAuthorizeCapsVisaCount(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	ch := newClearinghouse(t, kit)

	visas := make([]string, maxVisasPerPassport+1)
	for i := range visas {
		visas[i] = kit.grantVisa(t, nil)
	}

	if _, err := ch.Authorize(t.Context(), []string{kit.passport(t, visas, nil)}, testDataset); !errors.Is(err, ErrNoValidPassport) {
		t.Fatalf("error = %v, want ErrNoValidPassport", err)
	}
}

// TestAuthorizeRejectsInvalidEnvelopes pins the ga4gh_passport_v1 § 8.1 rule:
// a request containing a failing passport is rejected outright, whatever else
// it carries.
func TestAuthorizeRejectsInvalidEnvelopes(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	stranger := newIssuerKit(t, "https://stranger.example.org")
	ch := newClearinghouse(t, kit)

	goodVisa := kit.grantVisa(t, nil)
	invalid := map[string]string{
		"not a JWT":        "garbage",
		"untrusted iss":    stranger.passport(t, []string{goodVisa}, nil),
		"expired":          kit.passport(t, []string{goodVisa}, func(c *visa.PassportClaims) { c.Expires = refTime.Add(-time.Minute) }),
		"visa as envelope": goodVisa,
		"jku swapped": func() string {
			s := kit.signerWithJKU(t, "https://evil.example.org/jwks")
			signed, err := s.SignPassport(visa.PassportClaims{
				Issuer: kit.url, Subject: testSubject,
				IssuedAt: refTime.Add(-time.Minute), Expires: refTime.Add(time.Hour),
				Visas: []string{goodVisa},
			})
			if err != nil {
				t.Fatalf("sign passport: %v", err)
			}

			return signed
		}(),
		"signed by untrusted key": func() string {
			// The stranger's key under the trusted issuer's name: the trust
			// table selects the trusted keys and the signature must fail.
			s := stranger.signerWithJKU(t, kit.jwksURL)
			signed, err := s.SignPassport(visa.PassportClaims{
				Issuer: kit.url, Subject: testSubject,
				IssuedAt: refTime.Add(-time.Minute), Expires: refTime.Add(time.Hour),
				Visas: []string{goodVisa},
			})
			if err != nil {
				t.Fatalf("sign passport: %v", err)
			}

			return signed
		}(),
	}

	granting := kit.passport(t, []string{goodVisa}, nil)
	for name, bad := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := ch.Authorize(t.Context(), []string{bad}, testDataset); !errors.Is(err, ErrNoValidPassport) {
				t.Fatalf("alone: error = %v, want ErrNoValidPassport", err)
			}
			// A granting passport does not rescue a request carrying an
			// invalid one, in either order.
			if _, err := ch.Authorize(t.Context(), []string{granting, bad}, testDataset); !errors.Is(err, ErrNoValidPassport) {
				t.Fatalf("after granting: error = %v, want ErrNoValidPassport", err)
			}
			if _, err := ch.Authorize(t.Context(), []string{bad, granting}, testDataset); !errors.Is(err, ErrNoValidPassport) {
				t.Fatalf("before granting: error = %v, want ErrNoValidPassport", err)
			}
		})
	}
}

// TestAuthorizeMultiplePassports pins that a grant in any valid passport of
// the request suffices.
func TestAuthorizeMultiplePassports(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	ch := newClearinghouse(t, kit)

	empty := kit.passport(t, nil, nil)
	granting := kit.passport(t, []string{kit.grantVisa(t, nil)}, nil)

	if _, err := ch.Authorize(t.Context(), []string{empty, granting}, testDataset); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
}

// TestAuthorizeSecondTrustedIssuer pins that trust is per issuer: a passport
// from a second trusted issuer verifies against its own pinned keys.
func TestAuthorizeSecondTrustedIssuer(t *testing.T) {
	kitA := newIssuerKit(t, "https://issuer-a.example.org")
	kitB := newIssuerKit(t, "https://issuer-b.example.org")
	ch := newClearinghouse(t, kitA, kitB)

	visaB := kitB.grantVisa(t, nil)
	passportB := kitB.passport(t, []string{visaB}, nil)

	grant, err := ch.Authorize(t.Context(), []string{passportB}, testDataset)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if grant.Issuer != kitB.url {
		t.Errorf("grant issuer = %q, want %q", grant.Issuer, kitB.url)
	}
}
