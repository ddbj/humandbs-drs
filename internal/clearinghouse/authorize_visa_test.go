package clearinghouse

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

// badVisas builds the catalogue of visas that must be ignored by the
// clearinghouse, each derived from a well-formed grant visa by one deviation.
func badVisas(t *testing.T, kit, stranger *issuerKit) map[string]string {
	t.Helper()

	signAs := func(s *visa.Signer, c visa.Claims) string {
		t.Helper()
		signed, err := s.Sign(c)
		if err != nil {
			t.Fatalf("sign visa: %v", err)
		}

		return signed
	}

	bad := map[string]string{
		"not a JWT":            "garbage",
		"expired":              kit.grantVisa(t, func(c *visa.Claims) { c.Expires = refTime.Add(-time.Minute) }),
		"issued in the future": kit.grantVisa(t, func(c *visa.Claims) { c.IssuedAt = refTime.Add(time.Minute) }),
		"untrusted iss":        signAs(stranger.signer, func() visa.Claims { c := stranger.grantClaims(); return c }()),
		"iss of another trusted issuer": signAs(kit.signer, func() visa.Claims {
			// kit's key, but claiming the stranger's identity: the trust
			// table must select the claimed issuer's keys, not the signer's.
			c := kit.grantClaims()
			c.Issuer = stranger.url

			return c
		}()),
		"sub differs from passport": kit.grantVisa(t, func(c *visa.Claims) { c.Subject = "someone-else" }),
		"missing jku":               signAs(kit.signerWithJKU(t, ""), kit.grantClaims()),
		"missing value":             kit.grantVisa(t, func(c *visa.Claims) { c.Visa.Value = "" }),
		"missing source":            kit.grantVisa(t, func(c *visa.Claims) { c.Visa.Source = "" }),
		"missing asserted":          kit.grantVisa(t, func(c *visa.Claims) { c.Visa.Asserted = 0 }),
	}

	// jku equality is verbatim: every syntactic variation of the pinned URL
	// is a different URL and must be rejected.
	for name, jku := range map[string]string{
		"jku with trailing slash": kit.jwksURL + "/",
		"jku with explicit port":  "https://issuer.example.org:443/jwks",
		"jku with query":          kit.jwksURL + "?x=1",
		"jku with userinfo":       "https://issuer.example.org@evil.example.org/jwks",
		"jku swapped":             "https://evil.example.org/jwks",
	} {
		bad[name] = signAs(kit.signerWithJKU(t, jku), kit.grantClaims())
	}

	return bad
}

// TestAuthorizeIgnoresInvalidVisas pins the failure hierarchy: a failing visa
// inside a valid passport is ignored — alone it denies with 403, and it never
// blocks a valid grant visa in the same passport.
func TestAuthorizeIgnoresInvalidVisas(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	stranger := newIssuerKit(t, "https://stranger.example.org")
	ch := newClearinghouse(t, kit)

	good := kit.grantVisa(t, nil)
	for name, bad := range badVisas(t, kit, stranger) {
		t.Run(name, func(t *testing.T) {
			if _, err := ch.Authorize(t.Context(), []string{kit.passport(t, []string{bad}, nil)}, testDataset); !errors.Is(err, ErrNotAuthorized) {
				t.Fatalf("alone: error = %v, want ErrNotAuthorized", err)
			}
			if _, err := ch.Authorize(t.Context(), []string{kit.passport(t, []string{bad, good}, nil)}, testDataset); err != nil {
				t.Fatalf("with a good visa: %v", err)
			}
		})
	}
}

// TestAuthorizeDeniesNonGrantingVisas pins the visas that verify but do not
// grant the dataset.
func TestAuthorizeDeniesNonGrantingVisas(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	ch := newClearinghouse(t, kit)

	cases := map[string]func(*visa.Claims){
		"other dataset":        func(c *visa.Claims) { c.Visa.Value = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD999999" },
		"dataset case differs": func(c *visa.Claims) { c.Visa.Value = testDataset + "x" },
		"other visa type":      func(c *visa.Claims) { c.Visa.Type = "AffiliationAndRole" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			passport := kit.passport(t, []string{kit.grantVisa(t, mutate)}, nil)
			if _, err := ch.Authorize(t.Context(), []string{passport}, testDataset); !errors.Is(err, ErrNotAuthorized) {
				t.Fatalf("error = %v, want ErrNotAuthorized", err)
			}
		})
	}
}

func TestAuthorizeEmptyPassportDenies(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	ch := newClearinghouse(t, kit)

	if _, err := ch.Authorize(t.Context(), []string{kit.passport(t, nil, nil)}, testDataset); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("error = %v, want ErrNotAuthorized", err)
	}
}

// affiliationVisa signs an AffiliationAndRole visa, the companion that
// satisfies conditions.
func (k *issuerKit) affiliationVisa(t *testing.T, mutate func(*visa.Claims)) string {
	t.Helper()

	c := visa.Claims{
		Issuer:   k.url,
		Subject:  testSubject,
		IssuedAt: refTime.Add(-time.Minute),
		Expires:  refTime.Add(time.Hour),
		ID:       nextJTI(),
		Visa: visa.Object{
			Type:     "AffiliationAndRole",
			Asserted: refTime.Add(-24 * time.Hour).Unix(),
			Value:    "faculty@med.stanford.edu",
			Source:   "https://grid.ac/institutes/grid.240952.8",
			By:       "so",
		},
	}
	if mutate != nil {
		mutate(&c)
	}
	signed, err := k.signer.Sign(c)
	if err != nil {
		t.Fatalf("sign visa: %v", err)
	}

	return signed
}

// conditionalGrant is a grant visa whose validity requires a faculty
// AffiliationAndRole visa elsewhere in the passport.
func (k *issuerKit) conditionalGrant(t *testing.T) string {
	t.Helper()

	return k.grantVisa(t, func(c *visa.Claims) {
		c.Visa.Conditions = json.RawMessage(`[[{"type":"AffiliationAndRole","value":"const:faculty@med.stanford.edu","by":"const:so"}]]`)
	})
}

func TestAuthorizeConditions(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	ch := newClearinghouse(t, kit)

	authorize := func(visas ...string) error {
		_, err := ch.Authorize(t.Context(), []string{kit.passport(t, visas, nil)}, testDataset)

		return err
	}

	t.Run("satisfied by a companion visa", func(t *testing.T) {
		if err := authorize(kit.conditionalGrant(t), kit.affiliationVisa(t, nil)); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
	})

	t.Run("no companion visa", func(t *testing.T) {
		if err := authorize(kit.conditionalGrant(t)); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("error = %v, want ErrNotAuthorized", err)
		}
	})

	t.Run("companion with wrong role", func(t *testing.T) {
		companion := kit.affiliationVisa(t, func(c *visa.Claims) { c.Visa.Value = "student@med.stanford.edu" })
		if err := authorize(kit.conditionalGrant(t), companion); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("error = %v, want ErrNotAuthorized", err)
		}
	})

	t.Run("expired companion cannot satisfy", func(t *testing.T) {
		companion := kit.affiliationVisa(t, func(c *visa.Claims) { c.Expires = refTime.Add(-time.Minute) })
		if err := authorize(kit.conditionalGrant(t), companion); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("error = %v, want ErrNotAuthorized", err)
		}
	})

	t.Run("condition-bearing companion is no match target", func(t *testing.T) {
		companion := kit.affiliationVisa(t, func(c *visa.Claims) {
			c.Visa.Conditions = json.RawMessage(`[[{"type":"ResearcherStatus","by":"const:system"}]]`)
		})
		if err := authorize(kit.conditionalGrant(t), companion); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("error = %v, want ErrNotAuthorized", err)
		}
	})

	t.Run("companion in another passport does not count", func(t *testing.T) {
		p1 := kit.passport(t, []string{kit.conditionalGrant(t)}, nil)
		p2 := kit.passport(t, []string{kit.affiliationVisa(t, nil)}, nil)
		if _, err := ch.Authorize(t.Context(), []string{p1, p2}, testDataset); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("error = %v, want ErrNotAuthorized", err)
		}
	})

	t.Run("malformed conditions reject the visa", func(t *testing.T) {
		grant := kit.grantVisa(t, func(c *visa.Claims) {
			c.Visa.Conditions = json.RawMessage(`[[]]`)
		})
		if err := authorize(grant, kit.affiliationVisa(t, nil)); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("error = %v, want ErrNotAuthorized", err)
		}
	})

	t.Run("null conditions count as absent", func(t *testing.T) {
		grant := kit.grantVisa(t, func(c *visa.Claims) {
			c.Visa.Conditions = json.RawMessage(`null`)
		})
		if err := authorize(grant); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
	})

	t.Run("unsatisfied conditions do not block another grant visa", func(t *testing.T) {
		if err := authorize(kit.conditionalGrant(t), kit.grantVisa(t, nil)); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
	})
}
