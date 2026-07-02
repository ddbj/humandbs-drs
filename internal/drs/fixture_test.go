package drs_test

import (
	"context"
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

	"github.com/ddbj/humandbs-drs/internal/drs"
	"github.com/ddbj/humandbs-drs/internal/index"
	"github.com/ddbj/humandbs-drs/internal/storage"
)

const datasetURL = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001"

// fixture is a running DRS handler backed by a real filesystem tree indexed into
// a real SQLite database; only the FS and DB boundaries are exercised.
type fixture struct {
	srv     *httptest.Server
	ix      *index.Index
	records map[string]index.Record
	ids     []string
}

func testSettings() drs.Settings {
	return drs.Settings{
		PublicHost:     "drs.example.org",
		ServiceID:      "jp.ac.nig.ddbj.humandbs-drs",
		ServiceName:    "HumanDBs DRS",
		OrgName:        "DDBJ",
		OrgURL:         "https://www.ddbj.nig.ac.jp/",
		Version:        "test",
		TrustedIssuers: []string{"https://issuer.example.org"},
	}
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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(drs.NewHandler(ix, testSettings(), logger))

	return &fixture{srv: srv, ix: ix, records: records, ids: ids}
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
