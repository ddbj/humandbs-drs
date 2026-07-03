package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ddbj/humandbs-drs/internal/encryption"
)

const hexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// writeTestFile writes content into dir under name and returns the path.
func writeTestFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// TestRunEncryptsFile round-trips through the CLI: the written envelope must
// decrypt back to the source bytes under the same key.
func TestRunEncryptsFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestFile(t, dir, "key.hex", []byte(hexKey+"\n"))
	plain := bytes.Repeat([]byte("controlled data "), 100)
	srcPath := writeTestFile(t, dir, "plain.bin", plain)
	dstPath := filepath.Join(dir, "sealed.bin")

	if err := run([]string{"-key-file", keyPath, srcPath, dstPath}, io.Discard); err != nil {
		t.Fatalf("run: %v", err)
	}

	envelope, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := encryption.ReadKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encryption.NewAtRest(key, encryption.DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	r, size, err := enc.Reader(bytes.NewReader(envelope), int64(len(envelope)))
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	if size != int64(len(plain)) {
		t.Fatalf("plaintext size = %d, want %d", size, len(plain))
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted envelope differs from source")
	}
}

// TestRunRefusesExistingDestination pins the no-overwrite guarantee.
func TestRunRefusesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestFile(t, dir, "key.hex", []byte(hexKey))
	srcPath := writeTestFile(t, dir, "plain.bin", []byte("data"))
	dstPath := writeTestFile(t, dir, "existing.bin", []byte("keep me"))

	if err := run([]string{"-key-file", keyPath, srcPath, dstPath}, io.Discard); err == nil {
		t.Fatal("run overwrote an existing destination, want error")
	}
	kept, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != "keep me" {
		t.Fatalf("destination content = %q, want untouched", kept)
	}
}

// TestRunArgumentErrors rejects a missing key file flag, a bad argument count,
// and an unreadable key.
func TestRunArgumentErrors(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestFile(t, dir, "key.hex", []byte(hexKey))
	badKeyPath := writeTestFile(t, dir, "bad.hex", []byte("not-hex"))
	srcPath := writeTestFile(t, dir, "plain.bin", []byte("data"))

	for name, args := range map[string][]string{
		"no key-file":     {srcPath, filepath.Join(dir, "out1")},
		"missing dst":     {"-key-file", keyPath, srcPath},
		"extra arg":       {"-key-file", keyPath, srcPath, "a", "b"},
		"bad key":         {"-key-file", badKeyPath, srcPath, filepath.Join(dir, "out2")},
		"missing src":     {"-key-file", keyPath, filepath.Join(dir, "absent"), filepath.Join(dir, "out3")},
		"absent key file": {"-key-file", filepath.Join(dir, "nokey"), srcPath, filepath.Join(dir, "out4")},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}
