package visa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
)

// jwksView is the subset of a JWKS the tests inspect.
type jwksView struct {
	Keys []map[string]any `json:"keys"`
}

func parseJWKS(t *testing.T, entries ...KeyEntry) jwksView {
	t.Helper()

	set, err := PublicJWKS(entries...)
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}
	encoded, err := MarshalJWKS(set)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	var view jwksView
	if err := json.Unmarshal(encoded, &view); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}

	return view
}

func TestPublicJWKSPinsAlgorithmAndUsage(t *testing.T) {
	rsa := rsaKey(t)
	ec := ecKey(t)

	view := parseJWKS(t,
		KeyEntry{KeyID: "rsa-1", Public: rsa.Public()},
		KeyEntry{KeyID: "ec-1", Public: ec.Public()},
	)

	if len(view.Keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(view.Keys))
	}

	wantAlg := map[string]string{"rsa-1": "RS256", "ec-1": "ES256"}
	wantKty := map[string]string{"rsa-1": "RSA", "ec-1": "EC"}
	for _, key := range view.Keys {
		kid, _ := key["kid"].(string)
		if _, ok := wantAlg[kid]; !ok {
			t.Fatalf("unexpected kid %q", kid)
		}
		if key["alg"] != wantAlg[kid] {
			t.Errorf("kid %q alg = %v, want %s", kid, key["alg"], wantAlg[kid])
		}
		if key["use"] != "sig" {
			t.Errorf("kid %q use = %v, want sig", kid, key["use"])
		}
		if key["kty"] != wantKty[kid] {
			t.Errorf("kid %q kty = %v, want %s", kid, key["kty"], wantKty[kid])
		}
		if _, hasD := key["d"]; hasD {
			t.Errorf("kid %q leaks private component d", kid)
		}
	}
}

func TestPublicJWKSRejectsEmptyKid(t *testing.T) {
	if _, err := PublicJWKS(KeyEntry{KeyID: "", Public: rsaKey(t).Public()}); err == nil {
		t.Fatal("expected PublicJWKS to reject an empty kid, got nil")
	}
}

func TestPublicJWKSRejectsUnsupportedKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	cases := []struct {
		name string
		pub  crypto.PublicKey
	}{
		{"ed25519", pub},
		{"ecdsa P-384", p384PublicKey(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PublicJWKS(KeyEntry{KeyID: "k", Public: tc.pub}); !errors.Is(err, ErrUnsupportedKey) {
				t.Fatalf("error = %v, want ErrUnsupportedKey", err)
			}
		})
	}
}

func p384PublicKey(t *testing.T) crypto.PublicKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}

	return key.Public()
}
