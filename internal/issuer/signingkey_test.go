package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// writePKCS8PEM writes key to path as a PKCS#8 PEM file, the on-disk format
// LoadOrCreateSigningKey reads.
func writePKCS8PEM(t *testing.T, path string, key any) {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write PEM: %v", err)
	}
}

func TestLoadOrCreateSigningKeyGeneratesRSA2048(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")

	key, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	if got := key.N.BitLen(); got != 2048 {
		t.Errorf("generated key size = %d bits, want 2048", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat generated key file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key file permissions = %o, want 600", got)
	}
}

func TestLoadOrCreateSigningKeyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")

	created, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	loaded, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !created.Equal(loaded) {
		t.Error("reloaded key differs from the generated one")
	}
}

func TestLoadOrCreateSigningKeyLoadsExistingPKCS8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")
	want, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	writePKCS8PEM(t, path, want)

	got, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	if !want.Equal(got) {
		t.Error("loaded key differs from the one on disk")
	}
}

func TestLoadOrCreateSigningKeyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := LoadOrCreateSigningKey(path)
	if !errors.Is(err, ErrInvalidSigningKey) {
		t.Errorf("err = %v, want ErrInvalidSigningKey", err)
	}
}

func TestLoadOrCreateSigningKeyRejectsNonRSA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	writePKCS8PEM(t, path, ecKey)

	_, err = LoadOrCreateSigningKey(path)
	if !errors.Is(err, ErrInvalidSigningKey) {
		t.Errorf("err = %v, want ErrInvalidSigningKey", err)
	}
}

// rfc7638VectorKey rebuilds the RSA public key of RFC 7638 § 3.1, whose SHA-256
// JWK thumbprint is the published value below.
func rfc7638VectorKey(t *testing.T) *rsa.PublicKey {
	t.Helper()

	const modulus = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	nBytes, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		t.Fatalf("decode vector modulus: %v", err)
	}

	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: 65537}
}

func TestKeyIDMatchesRFC7638Vector(t *testing.T) {
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	got, err := KeyID(rfc7638VectorKey(t))
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if got != want {
		t.Errorf("KeyID = %q, want %q", got, want)
	}
}

func TestKeyIDDistinguishesKeys(t *testing.T) {
	a, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	b, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	idA1, err := KeyID(&a.PublicKey)
	if err != nil {
		t.Fatalf("KeyID(a): %v", err)
	}
	idA2, err := KeyID(&a.PublicKey)
	if err != nil {
		t.Fatalf("KeyID(a) again: %v", err)
	}
	idB, err := KeyID(&b.PublicKey)
	if err != nil {
		t.Fatalf("KeyID(b): %v", err)
	}

	if idA1 != idA2 {
		t.Errorf("KeyID not deterministic: %q vs %q", idA1, idA2)
	}
	if idA1 == idB {
		t.Errorf("distinct keys share KeyID %q", idA1)
	}
}

func TestKeyIDRejectsUnsupportedKey(t *testing.T) {
	if _, err := KeyID("not a key"); err == nil {
		t.Fatal("want error for unsupported key type, got nil")
	}
}

func TestLoadOrCreateSigningKeyReportsUnreadablePath(t *testing.T) {
	// A directory is neither readable as a key nor absent, so the error must
	// surface instead of being masked by generation.
	path := t.TempDir()

	_, err := LoadOrCreateSigningKey(path)
	if err == nil {
		t.Fatal("want error for a directory path, got nil")
	}
}
