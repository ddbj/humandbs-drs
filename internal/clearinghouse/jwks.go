package clearinghouse

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// FetchKeys retrieves the JWK set at url, the out-of-band pinning of a trusted
// issuer's keys done once at startup (architecture.md § "Clearinghouse 設計").
// Key rotation therefore takes effect on restart.
func FetchKeys(ctx context.Context, url string) (jwk.Set, error) {
	set, err := jwk.Fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("clearinghouse: fetch JWKS %s: %w", url, err)
	}
	if set.Len() == 0 {
		return nil, fmt.Errorf("clearinghouse: JWKS %s holds no keys", url)
	}

	return set, nil
}
