package clearinghouse

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

func TestFetchKeys(t *testing.T) {
	kit := newIssuerKit(t, "https://issuer.example.org")
	jwksJSON, err := visa.MarshalJWKS(kit.trusted.Keys)
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksJSON)
		case "/empty":
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case "/broken":
			_, _ = w.Write([]byte(`not json`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	t.Run("fetches and parses the pinned keys", func(t *testing.T) {
		set, err := FetchKeys(t.Context(), srv.URL+"/jwks")
		if err != nil {
			t.Fatalf("FetchKeys: %v", err)
		}
		if set.Len() != 1 {
			t.Fatalf("set.Len() = %d, want 1", set.Len())
		}
		key, ok := set.Key(0)
		if !ok {
			t.Fatal("set has no key at index 0")
		}
		kid, ok := key.KeyID()
		if !ok || kid != kit.kid {
			t.Errorf("kid = %q, want %q", kid, kit.kid)
		}
	})

	for name, path := range map[string]string{
		"missing document": "/nope",
		"empty key set":    "/empty",
		"broken document":  "/broken",
	} {
		t.Run(name+" is an error", func(t *testing.T) {
			if _, err := FetchKeys(t.Context(), srv.URL+path); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}
