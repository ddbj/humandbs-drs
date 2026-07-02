package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseManifest(t *testing.T) {
	in := `[
		{"root": "/data/a", "dataset_resource_url": "https://example.org/a"},
		{"root": "/data/b", "dataset_resource_url": "https://example.org/b"}
	]`
	ds, err := ParseManifest(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(ds) != 2 {
		t.Fatalf("parsed %d datasets, want 2", len(ds))
	}
	if ds[0].Root != "/data/a" || ds[0].URL != "https://example.org/a" {
		t.Fatalf("dataset 0 = %+v", ds[0])
	}
	if ds[1].Root != "/data/b" || ds[1].URL != "https://example.org/b" {
		t.Fatalf("dataset 1 = %+v", ds[1])
	}
}

func TestParseManifestRejects(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		invalidMani bool
	}{
		{"unknown field", `[{"root":"/a","dataset_resource_url":"u","extra":1}]`, false},
		{"trailing data", `[{"root":"/a","dataset_resource_url":"u"}] {}`, false},
		{"not an array", `{"root":"/a","dataset_resource_url":"u"}`, false},
		{"empty root", `[{"root":"","dataset_resource_url":"u"}]`, true},
		{"empty url", `[{"root":"/a","dataset_resource_url":""}]`, true},
		{"nul in url", `[{"root":"/a","dataset_resource_url":"u\u0000v"}]`, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseManifest(strings.NewReader(tt.in))
			if err == nil {
				t.Fatalf("expected error")
			}
			if tt.invalidMani && !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestNewFSBackendRejectsNestedRoots(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := NewFSBackend([]Dataset{
		{Root: root, URL: urlA},
		{Root: sub, URL: urlB},
	})
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("nested roots: error = %v, want ErrInvalidManifest", err)
	}
}

func TestNewFSBackendRejectsDuplicateRoots(t *testing.T) {
	root := t.TempDir()
	_, err := NewFSBackend([]Dataset{
		{Root: root, URL: urlA},
		{Root: root, URL: urlB},
	})
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("duplicate roots: error = %v, want ErrInvalidManifest", err)
	}
}

func TestNewFSBackendRejectsNonDir(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f")
	writeFile(t, file, "x")

	if _, err := NewFSBackend([]Dataset{{Root: file, URL: urlA}}); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("file as root: error = %v, want ErrInvalidManifest", err)
	}
}

func TestNewFSBackendRejectsMissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := NewFSBackend([]Dataset{{Root: missing, URL: urlA}}); err == nil {
		t.Fatalf("missing root: expected error")
	}
}

func TestNewFSBackendRejectsInvalidFields(t *testing.T) {
	if _, err := NewFSBackend([]Dataset{{Root: t.TempDir(), URL: ""}}); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("empty url: error = %v, want ErrInvalidManifest", err)
	}
}
