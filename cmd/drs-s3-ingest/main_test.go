package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// ingestArgs builds a full argument list with every required flag, letting a
// case drop or override pieces without sharing slices across cases.
func ingestArgs(extra ...string) []string {
	args := []string{
		"-endpoint", "http://s3.invalid",
		"-bucket", "bucket",
		"-dataset", "https://example.org/dataset-a",
		"-access-key", "key",
		"-secret-key", "secret",
	}

	return append(args, extra...)
}

// TestRunArgumentErrors rejects missing required flags, a non-canonical id,
// and a bad argument count. Every case must fail before any endpoint IO, so
// the endpoint host is an unresolvable placeholder.
func TestRunArgumentErrors(t *testing.T) {
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(payload, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, args := range map[string][]string{
		"no endpoint": {
			"-bucket", "bucket", "-dataset", "https://example.org/dataset-a",
			"-access-key", "key", "-secret-key", "secret", payload,
		},
		"no bucket": {
			"-endpoint", "http://s3.invalid", "-dataset", "https://example.org/dataset-a",
			"-access-key", "key", "-secret-key", "secret", payload,
		},
		"no dataset": {
			"-endpoint", "http://s3.invalid", "-bucket", "bucket",
			"-access-key", "key", "-secret-key", "secret", payload,
		},
		"no access-key": {
			"-endpoint", "http://s3.invalid", "-bucket", "bucket",
			"-dataset", "https://example.org/dataset-a", "-secret-key", "secret", payload,
		},
		"no secret-key": {
			"-endpoint", "http://s3.invalid", "-bucket", "bucket",
			"-dataset", "https://example.org/dataset-a", "-access-key", "key", payload,
		},
		"no file":      ingestArgs(),
		"two files":    ingestArgs(payload, payload),
		"bad id":       ingestArgs("-id", "not-a-uuid", payload),
		"uppercase id": ingestArgs("-id", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", payload),
		"urn id":       ingestArgs("-id", "urn:uuid:0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", payload),
		"unknown flag": ingestArgs("-no-such-flag", payload),
	} {
		if err := run(context.Background(), args, io.Discard); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}

// TestRunVersion prints the build version without needing any other flag.
func TestRunVersion(t *testing.T) {
	if err := run(context.Background(), []string{"-version"}, io.Discard); err != nil {
		t.Fatalf("run -version: %v", err)
	}
}
