package issuer

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

// visaBy is the `by` claim of every minted visa: the assertion is made by a DAC
// (architecture.md § "Issuer 設計").
const visaBy = "dac"

// PassportIssuer turns a subject's grants into a signed GA4GH Passport: a JWT
// whose ga4gh_passport_v1 claim carries one signed ControlledAccessGrants visa
// per grant.
type PassportIssuer struct {
	signer    *visa.Signer
	issuerURL string
	ttl       time.Duration
	now       func() time.Time
}

// PassportIssuerOption customizes a PassportIssuer.
type PassportIssuerOption func(*PassportIssuer)

// WithPassportClock overrides the clock that stamps iat and caps exp. It exists
// to make expiry boundaries testable; production callers omit it and get the
// wall clock.
func WithPassportClock(now func() time.Time) PassportIssuerOption {
	return func(p *PassportIssuer) {
		p.now = now
	}
}

// NewPassportIssuer builds a PassportIssuer that mints visas as issuerURL (the
// `iss` claim) with signer. ttl caps every visa's lifetime; see Passport.
func NewPassportIssuer(signer *visa.Signer, issuerURL string, ttl time.Duration, opts ...PassportIssuerOption) (*PassportIssuer, error) {
	if signer == nil {
		return nil, errors.New("issuer: passport issuer requires a signer")
	}
	if issuerURL == "" {
		return nil, errors.New("issuer: passport issuer requires an issuer URL")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("issuer: passport issuer requires a positive visa ttl, got %s", ttl)
	}

	p := &PassportIssuer{signer: signer, issuerURL: issuerURL, ttl: ttl, now: time.Now}
	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// Passport signs one visa per grant for subject, wraps them in a signed
// Passport, and returns its encoded JWT. Callers pass the subject's active
// grants (GrantStore.ActiveBySubject); the transform is 1:1 and does not
// re-check grant expiry. A visa expires at now + TTL, or at the grant's earlier
// expiry, so no visa outlives its grant nor the configured cap. The Passport
// envelope itself expires at now + TTL (architecture.md § "Issuer 設計").
func (p *PassportIssuer) Passport(subject string, grants []Grant) (string, error) {
	now := p.now()
	visas := make([]string, 0, len(grants))
	for _, g := range grants {
		exp := now.Add(p.ttl)
		if g.Expires != nil && g.Expires.Before(exp) {
			exp = *g.Expires
		}

		signed, err := p.signer.Sign(visa.Claims{
			Issuer:   p.issuerURL,
			Subject:  subject,
			IssuedAt: now,
			Expires:  exp,
			ID:       uuid.NewString(),
			Visa: visa.Object{
				Type:       visa.TypeControlledAccessGrants,
				Asserted:   g.Asserted.Unix(),
				Value:      g.DatasetID,
				Source:     g.DACSource,
				By:         visaBy,
				Conditions: g.Conditions,
			},
		})
		if err != nil {
			return "", fmt.Errorf("issuer: sign visa for %s: %w", g.DatasetID, err)
		}
		visas = append(visas, signed)
	}

	passport, err := p.signer.SignPassport(visa.PassportClaims{
		Issuer:   p.issuerURL,
		Subject:  subject,
		IssuedAt: now,
		Expires:  now.Add(p.ttl),
		ID:       uuid.NewString(),
		Visas:    visas,
	})
	if err != nil {
		return "", fmt.Errorf("issuer: sign passport: %w", err)
	}

	return passport, nil
}
