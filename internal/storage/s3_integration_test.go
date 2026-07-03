//go:build integration

package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ddbj/humandbs-drs/internal/encryption"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

// s3TestConfig reads the SeaweedFS connection from the environment, skipping the
// test when no endpoint is configured so the default `go test` stays green
// without a live backend. Run with, e.g.:
//
//	HUMANDBS_TEST_S3_ENDPOINT=http://localhost:8333 go test -tags integration ./internal/storage/
func s3TestConfig(t *testing.T) S3Config {
	t.Helper()
	endpoint := os.Getenv("HUMANDBS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("HUMANDBS_TEST_S3_ENDPOINT is not set; skipping SeaweedFS integration test")
	}

	return S3Config{
		Endpoint:       endpoint,
		Region:         getenvDefault("HUMANDBS_TEST_S3_REGION", "us-east-1"),
		Bucket:         "humandbs-test-" + uuid.NewString(),
		AccessKey:      getenvDefault("HUMANDBS_TEST_S3_ACCESS_KEY", "any"),
		SecretKey:      getenvDefault("HUMANDBS_TEST_S3_SECRET_KEY", "any"),
		ForcePathStyle: true,
	}
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return def
}

// newIntegrationBucket creates a fresh bucket and returns a backend over it.
func newIntegrationBucket(t *testing.T, cfg S3Config) *S3Backend {
	t.Helper()
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(cfg.Endpoint),
		Region:       cfg.Region,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		UsePathStyle: cfg.ForcePathStyle,
	})
	if _, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String(cfg.Bucket)}); err != nil {
		t.Fatalf("CreateBucket %q: %v", cfg.Bucket, err)
	}
	b, err := NewS3Backend(cfg)
	if err != nil {
		t.Fatalf("NewS3Backend: %v", err)
	}

	return b
}

func TestS3IntegrationPutScanOpen(t *testing.T) {
	cfg := s3TestConfig(t)
	b := newIntegrationBucket(t, cfg)
	ctx := context.Background()
	content := "controlled-access bytes over SeaweedFS"

	put, err := b.Put(ctx, urlA, strings.NewReader(content))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The index is recoverable from the bucket: a scan restores the minted id
	// and dataset from object metadata.
	var scanned *Entry
	if err := b.Scan(ctx, func(e Entry) error {
		if e.ID == put.ID {
			e := e
			scanned = &e
		}

		return nil
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if scanned == nil {
		t.Fatalf("scan did not recover put id %q", put.ID)
	}
	if scanned.DatasetURL != urlA || scanned.Size != int64(len(content)) {
		t.Fatalf("scanned entry %+v, want dataset %q size %d", *scanned, urlA, len(content))
	}

	rsc, err := b.Open(ctx, put.Location)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rsc.Close() }()
	got, err := io.ReadAll(rsc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != content {
		t.Fatalf("downloaded %q, want %q", got, content)
	}

	// A range read must reach the right bytes through the lazy seek reader.
	rangeRSC, err := b.Open(ctx, put.Location)
	if err != nil {
		t.Fatalf("Open (range): %v", err)
	}
	defer func() { _ = rangeRSC.Close() }()
	var buf bytes.Buffer
	if _, err := ReadRange(&buf, rangeRSC, int64(len(content)), 11, 6); err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if buf.String() != content[11:17] {
		t.Fatalf("range read = %q, want %q", buf.String(), content[11:17])
	}
}

func TestS3IntegrationAtRestRoundTrip(t *testing.T) {
	cfg := s3TestConfig(t)
	b := newIntegrationBucket(t, cfg)
	ctx := context.Background()

	key := bytes.Repeat([]byte{0x2b}, encryption.KeySize)
	prov, err := encryption.NewAtRest(key, 16)
	if err != nil {
		t.Fatalf("NewAtRest: %v", err)
	}
	plaintext := []byte("the (s3, at-rest) combination must deliver the same plaintext bytes")

	var envelope bytes.Buffer
	if err := prov.Encrypt(&envelope, bytes.NewReader(plaintext)); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	storedSize := int64(envelope.Len())

	put, err := b.Put(ctx, urlA, bytes.NewReader(envelope.Bytes()))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	rsc, err := b.Open(ctx, put.Location)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rsc.Close() }()

	plain, plainSize, err := prov.Reader(rsc, storedSize)
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	if plainSize != int64(len(plaintext)) {
		t.Fatalf("plaintext size = %d, want %d", plainSize, len(plaintext))
	}

	var full bytes.Buffer
	if _, err := ReadRange(&full, plain, plainSize, 0, plainSize); err != nil {
		t.Fatalf("ReadRange full: %v", err)
	}
	if !bytes.Equal(full.Bytes(), plaintext) {
		t.Fatalf("decrypted whole object mismatch")
	}

	var mid bytes.Buffer
	if _, err := ReadRange(&mid, plain, plainSize, 20, 10); err != nil {
		t.Fatalf("ReadRange mid: %v", err)
	}
	if !bytes.Equal(mid.Bytes(), plaintext[20:30]) {
		t.Fatalf("decrypted range mismatch: got %q, want %q", mid.Bytes(), plaintext[20:30])
	}
}
