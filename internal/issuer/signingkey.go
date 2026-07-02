package issuer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ErrInvalidSigningKey reports a signing-key file whose content is not a
// PKCS#8-encoded RSA private key.
var ErrInvalidSigningKey = errors.New("issuer: invalid signing key")

// signingKeyBits is the RSA modulus size for generated visa signing keys
// (architecture.md § "Issuer 設計").
const signingKeyBits = 2048

// LoadOrCreateSigningKey returns the issuer's visa signing key. It reads path
// as a PKCS#8 PEM file; when the file does not exist it generates an RSA-2048
// key, persists it at path with owner-only permissions, and returns it. Any
// other read failure, or a file that decodes to something other than an RSA
// private key, is an error so a misconfigured key never signs visas silently.
func LoadOrCreateSigningKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return generateSigningKey(path)
	case err != nil:
		return nil, fmt.Errorf("issuer: read signing key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: %s is not PEM", ErrInvalidSigningKey, path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse PKCS#8: %w", ErrInvalidSigningKey, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s holds %T, want RSA", ErrInvalidSigningKey, path, parsed)
	}

	return key, nil
}

// generateSigningKey mints a fresh RSA key and writes it to path as PKCS#8 PEM
// readable only by the owner.
func generateSigningKey(path string) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, signingKeyBits)
	if err != nil {
		return nil, fmt.Errorf("issuer: generate signing key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("issuer: encode signing key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("issuer: write signing key: %w", err)
	}

	return key, nil
}

// KeyID derives the JWKS `kid` for pub as its RFC 7638 JWK thumbprint (SHA-256,
// base64url without padding). The kid is a pure function of the key, so signer
// and JWKS stay consistent across restarts without storing extra state.
func KeyID(pub crypto.PublicKey) (string, error) {
	jwkKey, err := jwk.Import(pub)
	if err != nil {
		return "", fmt.Errorf("issuer: derive kid: %w", err)
	}
	sum, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("issuer: derive kid: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(sum), nil
}
