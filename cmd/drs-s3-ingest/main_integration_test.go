//go:build integration

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ddbj/humandbs-drs/internal/storage"
)

// TestIngestIntegrationRoundTrip drives the CLI against a live SeaweedFS: the
// first run must create the bucket, the second must reuse it, and a backend
// scan must recover both ingested ids from object metadata alone. Run with,
// e.g.:
//
//	HUMANDBS_TEST_S3_ENDPOINT=http://localhost:8333 go test -tags integration ./cmd/drs-s3-ingest/
func TestIngestIntegrationRoundTrip(t *testing.T) {
	endpoint := os.Getenv("HUMANDBS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("HUMANDBS_TEST_S3_ENDPOINT is not set; skipping SeaweedFS integration test")
	}

	dir := t.TempDir()
	payload := filepath.Join(dir, "payload.bin")
	content := []byte("ingested controlled-access bytes")
	if err := os.WriteFile(payload, content, 0o600); err != nil {
		t.Fatal(err)
	}

	bucket := "humandbs-ingest-" + uuid.NewString()
	datasetURL := "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001"
	ingest := func(id string) string {
		t.Helper()
		var out bytes.Buffer
		err := run(context.Background(), []string{
			"-endpoint", endpoint,
			"-bucket", bucket,
			"-access-key", "any",
			"-secret-key", "any",
			"-dataset", datasetURL,
			"-id", id,
			payload,
		}, &out)
		if err != nil {
			t.Fatalf("run (id %q): %v", id, err)
		}

		return strings.TrimSpace(out.String())
	}

	idA := uuid.NewString()
	if got := ingest(idA); got != idA {
		t.Fatalf("printed id %q, want %q", got, idA)
	}

	// A second ingest into the now-existing bucket must succeed: ensureBucket
	// treats an already-owned bucket as success.
	idB := uuid.NewString()
	if got := ingest(idB); got != idB {
		t.Fatalf("printed id %q, want %q", got, idB)
	}

	backend, err := storage.NewS3Backend(storage.S3Config{
		Endpoint:       endpoint,
		Region:         "us-east-1",
		Bucket:         bucket,
		AccessKey:      "any",
		SecretKey:      "any",
		ForcePathStyle: true,
	})
	if err != nil {
		t.Fatalf("NewS3Backend: %v", err)
	}
	got := map[string]storage.Entry{}
	if err := backend.Scan(context.Background(), func(e storage.Entry) error {
		got[e.ID] = e

		return nil
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, id := range []string{idA, idB} {
		e, ok := got[id]
		if !ok {
			t.Fatalf("scan did not recover id %q: %v", id, got)
		}
		if e.DatasetURL != datasetURL || e.Size != int64(len(content)) {
			t.Fatalf("scanned entry %+v, want dataset %q size %d", e, datasetURL, len(content))
		}
	}
}
