package drs_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ddbj/humandbs-drs/internal/clearinghouse"
	"github.com/ddbj/humandbs-drs/internal/drs"
	"github.com/ddbj/humandbs-drs/internal/index"
	"github.com/ddbj/humandbs-drs/internal/storage"
	"github.com/ddbj/humandbs-drs/internal/token"
	"github.com/ddbj/humandbs-drs/internal/visa"
)

const (
	datasetURL    = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001"
	testIssuerURL = "https://issuer.example.org"
	testJWKSURL   = testIssuerURL + "/jwks"
	testSubject   = "user-123"
)

// fixture is a running DRS handler backed by a real filesystem tree indexed into
// a real SQLite database, with a Clearinghouse trusting one test issuer whose
// signer mints real passports; only the FS and DB boundaries are exercised.
type fixture struct {
	srv     *httptest.Server
	ix      *index.Index
	records map[string]index.Record
	ids     []string
	signer  *visa.Signer
}

func testSettings() drs.Settings {
	return drs.Settings{
		PublicHost:     "drs.example.org",
		ServiceID:      "jp.ac.nig.ddbj.humandbs-drs",
		ServiceName:    "HumanDBs DRS",
		OrgName:        "DDBJ",
		OrgURL:         "https://www.ddbj.nig.ac.jp/",
		Version:        "test",
		TrustedIssuers: []string{testIssuerURL},
	}
}

// testAuthority builds the signer of the trusted test issuer and a
// Clearinghouse pinning its public key, plus a session token store.
func testAuthority(t *testing.T) (*visa.Signer, *clearinghouse.Clearinghouse, *token.Store) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "key-1"
	signer, err := visa.NewSigner(key, kid, testJWKSURL)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	keys, err := visa.PublicJWKS(visa.KeyEntry{KeyID: kid, Public: key.Public()})
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	ch, err := clearinghouse.New([]clearinghouse.Issuer{{URL: testIssuerURL, JWKSURL: testJWKSURL, Keys: keys}})
	if err != nil {
		t.Fatalf("clearinghouse.New: %v", err)
	}
	tokens, err := token.NewStore(5 * time.Minute)
	if err != nil {
		t.Fatalf("token.NewStore: %v", err)
	}

	return signer, ch, tokens
}

// buildFixture writes files (relative path -> content) under one dataset root,
// rebuilds the index, and serves the handler. The caller owns close.
func buildFixture(t *testing.T, files map[string]string) *fixture {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		writeFile(t, filepath.Join(root, rel), content)
	}

	backend, err := storage.NewFSBackend([]storage.Dataset{{Root: root, URL: datasetURL}})
	if err != nil {
		t.Fatalf("NewFSBackend: %v", err)
	}
	ix, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if _, err := ix.Rebuild(context.Background(), backend); err != nil {
		_ = ix.Close()
		t.Fatalf("Rebuild: %v", err)
	}
	list, err := ix.List(context.Background())
	if err != nil {
		_ = ix.Close()
		t.Fatalf("List: %v", err)
	}

	records := make(map[string]index.Record, len(list))
	ids := make([]string, 0, len(list))
	for _, rec := range list {
		records[rec.ID] = rec
		ids = append(ids, rec.ID)
	}

	signer, ch, tokens := testAuthority(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(drs.NewHandler(ix, ch, tokens, testSettings(), logger))

	return &fixture{srv: srv, ix: ix, records: records, ids: ids, signer: signer}
}

// newFixture builds a fixture whose resources are released at test end.
func newFixture(t *testing.T, files map[string]string) *fixture {
	t.Helper()
	f := buildFixture(t, files)
	t.Cleanup(f.close)

	return f
}

func (f *fixture) close() {
	f.srv.Close()
	_ = f.ix.Close()
}

// url builds an absolute request URL under the DRS base path.
func (f *fixture) url(path string) string {
	return f.srv.URL + drs.BasePath + path
}

// grantVisa mints a visa asserting that a DAC granted testSubject access to
// dataset, valid for an hour from now.
func (f *fixture) grantVisa(t *testing.T, dataset string) string {
	t.Helper()

	now := time.Now()
	signed, err := f.signer.Sign(visa.Claims{
		Issuer:   testIssuerURL,
		Subject:  testSubject,
		IssuedAt: now,
		Expires:  now.Add(time.Hour),
		ID:       "test-grant",
		Visa: visa.Object{
			Type:     visa.TypeControlledAccessGrants,
			Asserted: now.Add(-24 * time.Hour).Unix(),
			Value:    dataset,
			Source:   "https://ddbj.nig.ac.jp/dac",
			By:       "dac",
		},
	})
	if err != nil {
		t.Fatalf("sign visa: %v", err)
	}

	return signed
}

// passport wraps visas in a signed Passport for testSubject.
func (f *fixture) passport(t *testing.T, visas ...string) string {
	t.Helper()

	now := time.Now()
	signed, err := f.signer.SignPassport(visa.PassportClaims{
		Issuer:   testIssuerURL,
		Subject:  testSubject,
		IssuedAt: now,
		Expires:  now.Add(time.Hour),
		Visas:    visas,
	})
	if err != nil {
		t.Fatalf("sign passport: %v", err)
	}

	return signed
}

// postPassports POSTs a passports body to path and returns the drained
// response.
func (f *fixture) postPassports(t *testing.T, path string, passports ...string) *http.Response {
	t.Helper()

	body, err := json.Marshal(map[string]any{"passports": passports})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	resp, err := http.Post(f.url(path), "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}

	return resp
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

// decodeBody decodes a JSON response body into dst without closing it; the
// caller closes the body.
func decodeBody(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode body: %v", err)
	}
}
