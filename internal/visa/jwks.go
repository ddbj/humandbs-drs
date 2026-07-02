package visa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// KeyEntry pairs a public key with the key ID that identifies it in a JWKS.
type KeyEntry struct {
	KeyID  string
	Public crypto.PublicKey
}

// PublicJWKS builds a verification JWK set from public keys. Each key is tagged
// with its `kid`, `use=sig`, and its pinned signing algorithm (RS256 for RSA,
// ES256 for ECDSA P-256). Pinning `alg` on the key is what constrains a Verifier
// to that algorithm, which together with the header allowlist blocks
// algorithm-confusion attacks.
func PublicJWKS(entries ...KeyEntry) (jwk.Set, error) {
	set := jwk.NewSet()
	for _, entry := range entries {
		key, err := publicJWK(entry)
		if err != nil {
			return nil, err
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("visa: add key %q to JWKS: %w", entry.KeyID, err)
		}
	}

	return set, nil
}

// MarshalJWKS serializes a JWK set to the JSON representation a /jwks endpoint
// serves.
func MarshalJWKS(set jwk.Set) ([]byte, error) {
	encoded, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("visa: marshal JWKS: %w", err)
	}

	return encoded, nil
}

// publicJWK converts one entry into a JWK carrying its kid, algorithm, and usage.
func publicJWK(entry KeyEntry) (jwk.Key, error) {
	if entry.KeyID == "" {
		return nil, fmt.Errorf("visa: JWKS entry requires a kid")
	}

	alg, err := signatureAlgForPublicKey(entry.Public)
	if err != nil {
		return nil, err
	}

	key, err := jwk.Import(entry.Public)
	if err != nil {
		return nil, fmt.Errorf("visa: import public key %q: %w", entry.KeyID, err)
	}

	fields := map[string]any{
		jwk.KeyIDKey:     entry.KeyID,
		jwk.AlgorithmKey: alg,
		jwk.KeyUsageKey:  jwk.ForSignature.String(),
	}
	for name, value := range fields {
		if err := key.Set(name, value); err != nil {
			return nil, fmt.Errorf("visa: set %s on key %q: %w", name, entry.KeyID, err)
		}
	}

	return key, nil
}

// signatureAlgForPublicKey maps a public key to its GA4GH signing algorithm,
// mirroring signatureAlgForPrivateKey.
func signatureAlgForPublicKey(key crypto.PublicKey) (jwa.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return jwa.RS256(), nil
	case *ecdsa.PublicKey:
		return ecdsaAlg(k.Curve)
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("%w: %T", ErrUnsupportedKey, key)
	}
}
