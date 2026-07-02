package issuer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

// fakeIDP serves the OIDC surface NewOIDCVerifier needs — the discovery
// document and a JWKS — from httptest, and mints access tokens signed with its
// key. It stands in for Keycloak at the process boundary.
type fakeIDP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate IdP key: %v", err)
	}
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	set, err := visa.PublicJWKS(visa.KeyEntry{KeyID: kid, Public: &key.PublicKey})
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	jwksJSON, err := visa.MarshalJWKS(set)
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}

	f := &fakeIDP{key: key, kid: kid}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, f.srv.URL, f.srv.URL+"/jwks")
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	return f
}

// accessClaims returns the claims of an access token valid at refTime for sub.
func (f *fakeIDP) accessClaims(sub string) map[string]any {
	return map[string]any{
		"iss": f.srv.URL,
		"sub": sub,
		"aud": "humandbs",
		"iat": refTime.Add(-time.Minute).Unix(),
		"exp": refTime.Add(5 * time.Minute).Unix(),
	}
}

// token mints an access token from accessClaims(sub); mod, when non-nil,
// tweaks the claims before signing.
func (f *fakeIDP) token(t *testing.T, sub string, mod func(claims map[string]any)) string {
	t.Helper()

	claims := f.accessClaims(sub)
	if mod != nil {
		mod(claims)
	}

	return signToken(t, f.key, jwa.RS256(), f.kid, claims)
}

// newVerifier builds an OIDCVerifier bound to this IdP, pinned to refTime.
func (f *fakeIDP) newVerifier(t *testing.T, clientID string) *OIDCVerifier {
	t.Helper()

	v, err := NewOIDCVerifier(context.Background(), f.srv.URL, clientID, WithOIDCClock(fixedClock(refTime)))
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}

	return v
}

func TestOIDCVerifierAcceptsValidToken(t *testing.T) {
	idp := newFakeIDP(t)
	v := idp.newVerifier(t, "")

	sub, err := v.Verify(context.Background(), idp.token(t, "alice", nil))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sub != "alice" {
		t.Errorf("subject = %q, want %q", sub, "alice")
	}
}

func TestOIDCVerifierRejectsBadTokens(t *testing.T) {
	idp := newFakeIDP(t)
	stranger := newFakeIDP(t)
	v := idp.newVerifier(t, "")

	tests := []struct {
		name  string
		token string
	}{
		{"garbage", "not-a-jwt"},
		{"expired", idp.token(t, "alice", func(c map[string]any) {
			c["exp"] = refTime.Add(-time.Minute).Unix()
		})},
		{"issued by another provider", stranger.token(t, "alice", nil)},
		{"signed by another key", signToken(t, stranger.key, jwa.RS256(), idp.kid, idp.accessClaims("alice"))},
		{"hmac signature", signToken(t, []byte("0123456789abcdef0123456789abcdef"), jwa.HS256(), idp.kid, idp.accessClaims("alice"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tt.token)
			if !errors.Is(err, ErrInvalidAccessToken) {
				t.Errorf("err = %v, want ErrInvalidAccessToken", err)
			}
		})
	}
}

func TestOIDCVerifierAudience(t *testing.T) {
	idp := newFakeIDP(t)

	t.Run("matching audience accepted", func(t *testing.T) {
		v := idp.newVerifier(t, "humandbs")
		if _, err := v.Verify(context.Background(), idp.token(t, "alice", nil)); err != nil {
			t.Errorf("Verify: %v", err)
		}
	})
	t.Run("wrong audience rejected", func(t *testing.T) {
		v := idp.newVerifier(t, "other-client")
		_, err := v.Verify(context.Background(), idp.token(t, "alice", nil))
		if !errors.Is(err, ErrInvalidAccessToken) {
			t.Errorf("err = %v, want ErrInvalidAccessToken", err)
		}
	})
	t.Run("empty client id skips audience check", func(t *testing.T) {
		v := idp.newVerifier(t, "")
		token := idp.token(t, "alice", func(c map[string]any) {
			c["aud"] = "someone-else"
		})
		if _, err := v.Verify(context.Background(), token); err != nil {
			t.Errorf("Verify: %v", err)
		}
	})
}

func TestNewOIDCVerifierFailsWhenDiscoveryUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	if _, err := NewOIDCVerifier(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("want error for unreachable provider, got nil")
	}
}

func TestNewOIDCVerifierFailsOnIssuerMismatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"issuer":"https://evil.example","jwks_uri":"https://evil.example/jwks"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if _, err := NewOIDCVerifier(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("want error for issuer mismatch, got nil")
	}
}

// signToken signs claims with key under the given algorithm and kid.
func signToken(t *testing.T, key any, alg jwa.SignatureAlgorithm, kid string, claims map[string]any) string {
	t.Helper()

	b := jwt.NewBuilder()
	for name, value := range claims {
		b = b.Claim(name, value)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return string(signed)
}
