package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

// handlerKit is a full issuer HTTP stack: a fake IdP as the authN boundary, a
// real grant store and passport issuer, and a Verifier trusting the issuer's
// signing key. Everything is pinned to refTime.
type handlerKit struct {
	idp      *fakeIDP
	store    *GrantStore
	srv      *httptest.Server
	verifier *visa.Verifier
}

func newHandlerKit(t *testing.T) *handlerKit {
	t.Helper()

	idp := newFakeIDP(t)
	store := newStore(t, fixedClock(refTime))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	signer, err := visa.NewSigner(key, kid, testJKU)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	passport, err := NewPassportIssuer(signer, testIssuerURL, testTTL, WithPassportClock(fixedClock(refTime)))
	if err != nil {
		t.Fatalf("NewPassportIssuer: %v", err)
	}
	set, err := visa.PublicJWKS(visa.KeyEntry{KeyID: kid, Public: &key.PublicKey})
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	jwksJSON, err := visa.MarshalJWKS(set)
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}

	h := NewHandler(idp.newVerifier(t, ""), store, passport, jwksJSON, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &handlerKit{
		idp:      idp,
		store:    store,
		srv:      srv,
		verifier: visa.NewVerifier(set, visa.WithClock(fixedClock(refTime))),
	}
}

// httpResult is a drained HTTP response: status, headers, and the full body.
type httpResult struct {
	status int
	header http.Header
	body   []byte
}

// get performs a GET with an optional bearer token and returns the drained
// response.
func (k *handlerKit) get(t *testing.T, path, token string) httpResult {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, k.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return httpResult{status: resp.StatusCode, header: resp.Header, body: body}
}

// seedGrant stores a grant for subject on dataset, applying mod when non-nil.
func (k *handlerKit) seedGrant(t *testing.T, subject, dataset string, mod func(*Grant)) Grant {
	t.Helper()

	g := sampleGrant()
	g.Subject = subject
	g.DatasetID = dataset
	if mod != nil {
		mod(&g)
	}
	if err := k.store.Put(t.Context(), g); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	return g
}

func TestPermissionsReturnsPassportOfActiveGrants(t *testing.T) {
	k := newHandlerKit(t)
	k.seedGrant(t, "alice", "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1", nil)
	k.seedGrant(t, "alice", "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD2", nil)
	k.seedGrant(t, "bob", "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD3", nil)

	visas := k.visasOf(t, k.get(t, "/permissions/alice", k.idp.token(t, "alice", nil)))

	values := make(map[string]bool)
	for _, raw := range visas {
		claims, err := k.verifier.Verify(raw)
		if err != nil {
			t.Fatalf("Verify minted visa: %v", err)
		}
		if claims.Subject != "alice" {
			t.Errorf("visa sub = %q, want alice", claims.Subject)
		}
		values[claims.Visa.Value] = true
	}
	want := map[string]bool{
		"https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1": true,
		"https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD2": true,
	}
	if len(visas) != 2 || values["https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD3"] {
		t.Fatalf("visa datasets = %v, want %v", values, want)
	}
	for dataset := range want {
		if !values[dataset] {
			t.Errorf("missing visa for %s", dataset)
		}
	}
}

func TestPermissionsEmptyWhenNoGrants(t *testing.T) {
	k := newHandlerKit(t)

	res := k.get(t, "/permissions/alice", k.idp.token(t, "alice", nil))
	// A user without grants still receives a verifiable passport; its visa
	// array is just empty.
	if visas := k.visasOf(t, res); len(visas) != 0 {
		t.Errorf("visas = %v, want none", visas)
	}
}

func TestPermissionsExcludesLapsedGrants(t *testing.T) {
	k := newHandlerKit(t)
	// One grant lapsed an hour ago, one lapses exactly now; neither is active.
	k.seedGrant(t, "alice", "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1", func(g *Grant) {
		g.Expires = timePtr(refTime.Add(-time.Hour))
	})
	k.seedGrant(t, "alice", "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD2", func(g *Grant) {
		g.Expires = timePtr(refTime)
	})

	if visas := k.visasOf(t, k.get(t, "/permissions/alice", k.idp.token(t, "alice", nil))); len(visas) != 0 {
		t.Errorf("visas = %v, want none for lapsed grants", visas)
	}
}

func TestPermissionsRequiresBearerToken(t *testing.T) {
	k := newHandlerKit(t)

	res := k.get(t, "/permissions/alice", "")
	if res.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", res.status)
	}
	if res.header.Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate challenge")
	}
}

func TestPermissionsRejectsInvalidTokens(t *testing.T) {
	k := newHandlerKit(t)
	k.seedGrant(t, "alice", "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1", nil)

	tests := []struct {
		name  string
		token string
	}{
		{"garbage", "not-a-jwt"},
		{"expired", k.idp.token(t, "alice", func(c map[string]any) {
			c["exp"] = refTime.Add(-time.Minute).Unix()
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if res := k.get(t, "/permissions/alice", tt.token); res.status != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", res.status)
			}
		})
	}
}

func TestPermissionsRejectsSubjectMismatch(t *testing.T) {
	k := newHandlerKit(t)
	k.seedGrant(t, "bob", "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1", nil)

	if res := k.get(t, "/permissions/bob", k.idp.token(t, "alice", nil)); res.status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", res.status)
	}
}

func TestPermissionsRejectsOtherMethods(t *testing.T) {
	k := newHandlerKit(t)

	resp, err := http.Post(k.srv.URL+"/permissions/alice", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestJWKSServesVerificationKeysWithoutPrivateMaterial(t *testing.T) {
	k := newHandlerKit(t)
	grant := k.seedGrant(t, "alice", "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1", nil)

	res := k.get(t, "/jwks", "")
	if res.status != http.StatusOK {
		t.Fatalf("status = %d, body %s", res.status, res.body)
	}
	if got := res.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	set, err := jwk.Parse(res.body)
	if err != nil {
		t.Fatalf("parse served JWKS: %v", err)
	}
	for i := range set.Len() {
		key, _ := set.Key(i)
		if _, hasD := key.(jwk.RSAPrivateKey); hasD {
			t.Fatal("served JWKS contains a private key")
		}
	}

	// A passport minted via /permissions must verify against the served JWKS,
	// envelope and visa alike.
	verifier := visa.NewVerifier(set, visa.WithClock(fixedClock(refTime)))
	pc, err := verifier.VerifyPassport(decodePassportJWT(t, k.get(t, "/permissions/alice", k.idp.token(t, "alice", nil))))
	if err != nil {
		t.Fatalf("verify passport against served JWKS: %v", err)
	}
	if len(pc.Visas) != 1 {
		t.Fatalf("len(visas) = %d, want 1", len(pc.Visas))
	}
	claims, err := verifier.Verify(pc.Visas[0])
	if err != nil {
		t.Fatalf("verify against served JWKS: %v", err)
	}
	if claims.Visa.Value != grant.DatasetID {
		t.Errorf("visa value = %q, want %q", claims.Visa.Value, grant.DatasetID)
	}
}

// decodePassportJWT asserts a 200 response and returns the raw Passport JWT.
func decodePassportJWT(t *testing.T, res httpResult) string {
	t.Helper()

	if res.status != http.StatusOK {
		t.Fatalf("status = %d, body %s", res.status, res.body)
	}
	var pr passportResponse
	if err := json.Unmarshal(res.body, &pr); err != nil {
		t.Fatalf("decode passport: %v (body %s)", err, res.body)
	}
	if pr.Passport == "" {
		t.Fatalf("body %s carries no passport", res.body)
	}

	return pr.Passport
}

// visasOf asserts a 200 response, verifies the Passport envelope, and returns
// the embedded visas.
func (k *handlerKit) visasOf(t *testing.T, res httpResult) []string {
	t.Helper()

	pc, err := k.verifier.VerifyPassport(decodePassportJWT(t, res))
	if err != nil {
		t.Fatalf("verify passport envelope: %v", err)
	}

	return pc.Visas
}
