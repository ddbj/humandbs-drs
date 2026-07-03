package issuer

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"pgregory.net/rapid"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

// TestPassportGrantSetsRoundTrip checks over arbitrary grant sets that Passport
// mints a verifiable envelope holding a 1:1 transform of the grants: each grant
// yields exactly one visa whose claims mirror it, exp never exceeds now+TTL,
// jtis are unique, the visa subject is the requested one regardless of the
// grant rows, and a grant already expired at issue time yields a visa the
// verifier rejects as expired.
func TestPassportGrantSetsRoundTrip(t *testing.T) {
	p, verifier := newPassportKit(t, fixedClock(refTime))

	rapid.Check(t, func(rt *rapid.T) {
		subject := rapid.SampledFrom(pbtSubjects).Draw(rt, "subject")
		grants := make([]Grant, rapid.IntRange(0, 4).Draw(rt, "n"))
		for i := range grants {
			grants[i] = drawGrant(rt, fmt.Sprintf("g%d", i))
		}

		token, err := p.Passport(subject, grants)
		if err != nil {
			rt.Fatalf("Passport: %v", err)
		}
		pc, err := verifier.VerifyPassport(token)
		if err != nil {
			rt.Fatalf("VerifyPassport: %v", err)
		}
		if pc.Subject != subject {
			rt.Fatalf("passport sub = %q, want %q", pc.Subject, subject)
		}
		if want := refTime.Add(testTTL); !pc.Expires.Equal(want) {
			rt.Fatalf("passport exp = %s, want %s", pc.Expires, want)
		}
		if len(pc.Visas) != len(grants) {
			rt.Fatalf("len(visas) = %d, want %d", len(pc.Visas), len(grants))
		}

		jtis := make(map[string]bool)
		for i, raw := range pc.Visas {
			g := grants[i]
			wantExp := refTime.Add(testTTL)
			if g.Expires != nil && g.Expires.Before(wantExp) {
				wantExp = *g.Expires
			}

			claims, err := verifier.Verify(raw)
			if !wantExp.After(refTime) {
				// The grant had already lapsed when the visa was minted, so the
				// verifier must reject it as expired.
				if !errors.Is(err, visa.ErrTokenExpired) {
					rt.Fatalf("visa %d: err = %v, want ErrTokenExpired", i, err)
				}

				continue
			}
			if err != nil {
				rt.Fatalf("visa %d: Verify: %v", i, err)
			}

			if claims.Subject != subject {
				rt.Fatalf("visa %d: sub = %q, want %q", i, claims.Subject, subject)
			}
			if !claims.IssuedAt.Equal(refTime) {
				rt.Fatalf("visa %d: iat = %s, want %s", i, claims.IssuedAt, refTime)
			}
			if !claims.Expires.Equal(wantExp) {
				rt.Fatalf("visa %d: exp = %s, want %s", i, claims.Expires, wantExp)
			}
			if claims.Visa.Type != visa.TypeControlledAccessGrants {
				rt.Fatalf("visa %d: type = %q", i, claims.Visa.Type)
			}
			if claims.Visa.Value != g.DatasetID || claims.Visa.Source != g.DACSource {
				rt.Fatalf("visa %d: value/source = %q/%q, want %q/%q",
					i, claims.Visa.Value, claims.Visa.Source, g.DatasetID, g.DACSource)
			}
			if claims.Visa.Asserted != g.Asserted.Unix() {
				rt.Fatalf("visa %d: asserted = %d, want %d", i, claims.Visa.Asserted, g.Asserted.Unix())
			}
			if !bytes.Equal(claims.Visa.Conditions, g.Conditions) {
				rt.Fatalf("visa %d: conditions = %s, want %s", i, claims.Visa.Conditions, g.Conditions)
			}
			if jtis[claims.ID] {
				rt.Fatalf("visa %d: duplicate jti %q", i, claims.ID)
			}
			jtis[claims.ID] = true
		}
	})
}
