package issuer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrInvalidAccessToken reports an access token that failed verification:
// bad signature, untrusted issuer, disallowed algorithm, wrong audience, or
// expiry. Handlers map it to 401.
var ErrInvalidAccessToken = errors.New("issuer: invalid access token")

// OIDCVerifier validates Keycloak access tokens against the provider's
// published keys and issuer (architecture.md § "Issuer 設計").
type OIDCVerifier struct {
	verifier *oidc.IDTokenVerifier
}

// OIDCVerifierOption customizes token verification.
type OIDCVerifierOption func(*oidc.Config)

// WithOIDCClock overrides the clock used for the token expiry check. It exists
// to make temporal boundaries testable; production callers omit it and get the
// wall clock.
func WithOIDCClock(now func() time.Time) OIDCVerifierOption {
	return func(c *oidc.Config) {
		c.Now = now
	}
}

// NewOIDCVerifier discovers the OIDC provider at issuerURL and returns a
// verifier for its access tokens. Signatures are restricted to RS256/ES256,
// matching the visa allowlist. clientID, when non-empty, must appear in the
// token's `aud`; empty skips the audience check, since Keycloak access tokens
// carry an audience only when a dedicated mapper is configured. Discovery uses
// the HTTP client bound to ctx (oidc.ClientContext), and a provider that cannot
// be reached is a startup error rather than a deferred one.
func NewOIDCVerifier(ctx context.Context, issuerURL, clientID string, opts ...OIDCVerifierOption) (*OIDCVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("issuer: discover oidc provider %s: %w", issuerURL, err)
	}

	cfg := &oidc.Config{
		ClientID:             clientID,
		SkipClientIDCheck:    clientID == "",
		SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &OIDCVerifier{verifier: provider.Verifier(cfg)}, nil
}

// Verify checks raw and returns the authenticated subject. Any verification
// failure is reported as ErrInvalidAccessToken with the cause attached.
func (v *OIDCVerifier) Verify(ctx context.Context, raw string) (string, error) {
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidAccessToken, err)
	}

	return token.Subject, nil
}
