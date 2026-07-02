package index_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ddbj/humandbs-drs/internal/index"
	"github.com/ddbj/humandbs-drs/internal/storage"
)

const urlA = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001"

// writeFile writes content to path, creating parent directories. The index tests
// scan real files in t.TempDir; only the FS boundary is exercised, nothing is
// mocked.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

func newBackend(t *testing.T, datasets ...storage.Dataset) *storage.FSBackend {
	t.Helper()
	b, err := storage.NewFSBackend(datasets)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func openIndex(t *testing.T) *index.Index {
	t.Helper()
	ix, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ix.Close() })

	return ix
}

func TestRebuildIndexesObjects(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "hello")
	writeFile(t, filepath.Join(root, "sub", "b.bin"), "worldworld")

	b := newBackend(t, storage.Dataset{Root: root, URL: urlA})
	ix := openIndex(t)
	ctx := context.Background()

	n, err := ix.Rebuild(ctx, b)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if n != 2 {
		t.Fatalf("indexed %d objects, want 2", n)
	}

	recs, err := ix.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("listed %d objects, want 2", len(recs))
	}

	want := map[string]string{
		storage.ObjectID(urlA, "a.txt"):     "hello",
		storage.ObjectID(urlA, "sub/b.bin"): "worldworld",
	}
	for id, content := range want {
		r, err := ix.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get(%q): %v", id, err)
		}
		if r.DatasetURL != urlA {
			t.Fatalf("object %q: dataset = %q, want %q", id, r.DatasetURL, urlA)
		}
		if r.Size != int64(len(content)) {
			t.Fatalf("object %q: size = %d, want %d", id, r.Size, len(content))
		}
		if r.SHA256 != sha256hex(content) {
			t.Fatalf("object %q: sha256 = %q, want %q", id, r.SHA256, sha256hex(content))
		}
		info, err := os.Stat(r.Location)
		if err != nil {
			t.Fatal(err)
		}
		if r.CreatedAt.Unix() != info.ModTime().Unix() {
			t.Fatalf("object %q: created_at = %d, want file mtime %d",
				id, r.CreatedAt.Unix(), info.ModTime().Unix())
		}
	}
}

// TestRebuildDeterministicAfterNuke rebuilds the same tree into two independent
// index files: nuking the index and rescanning must restore identical rows,
// including ids, checksums, and created times (architecture.md § "index").
func TestRebuildDeterministicAfterNuke(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "x"), "111")
	writeFile(t, filepath.Join(root, "d", "y"), "2222")
	writeFile(t, filepath.Join(root, "empty"), "")
	b := newBackend(t, storage.Dataset{Root: root, URL: urlA})

	first := rebuildAndList(t, b)
	second := rebuildAndList(t, b)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("rebuild not deterministic:\nfirst  %+v\nsecond %+v", first, second)
	}
	if len(first) != 3 {
		t.Fatalf("indexed %d objects, want 3", len(first))
	}
}

func rebuildAndList(t *testing.T, b storage.Backend) []index.Record {
	t.Helper()
	ix := openIndex(t)
	ctx := context.Background()
	if _, err := ix.Rebuild(ctx, b); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	recs, err := ix.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	return recs
}

func TestRebuildReconcilesAddsAndRemovals(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "keep"), "k")
	writeFile(t, filepath.Join(root, "gone"), "g")
	b := newBackend(t, storage.Dataset{Root: root, URL: urlA})
	ix := openIndex(t)
	ctx := context.Background()

	if n, err := ix.Rebuild(ctx, b); err != nil || n != 2 {
		t.Fatalf("initial Rebuild: n=%d err=%v, want n=2", n, err)
	}

	writeFile(t, filepath.Join(root, "added"), "a")
	if n, err := ix.Rebuild(ctx, b); err != nil || n != 3 {
		t.Fatalf("Rebuild after add: n=%d err=%v, want n=3", n, err)
	}
	if _, err := ix.Get(ctx, storage.ObjectID(urlA, "added")); err != nil {
		t.Fatalf("added object not indexed: %v", err)
	}

	if err := os.Remove(filepath.Join(root, "gone")); err != nil {
		t.Fatal(err)
	}
	if n, err := ix.Rebuild(ctx, b); err != nil || n != 2 {
		t.Fatalf("Rebuild after remove: n=%d err=%v, want n=2", n, err)
	}
	if _, err := ix.Get(ctx, storage.ObjectID(urlA, "gone")); !errors.Is(err, index.ErrObjectNotFound) {
		t.Fatalf("removed object still indexed: err=%v", err)
	}
}

func TestGetMissingObject(t *testing.T) {
	if _, err := openIndex(t).Get(context.Background(), "no-such-id"); !errors.Is(err, index.ErrObjectNotFound) {
		t.Fatalf("Get missing: err=%v, want ErrObjectNotFound", err)
	}
}

func TestRebuildRejectsCollidingIDs(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	writeFile(t, filepath.Join(rootA, "dup.txt"), "1")
	writeFile(t, filepath.Join(rootB, "dup.txt"), "2")

	// Two disjoint roots labeled with the same dataset URL make "dup.txt" resolve
	// to one id from two files: an ambiguous manifest Rebuild must reject.
	b := newBackend(t,
		storage.Dataset{Root: rootA, URL: urlA},
		storage.Dataset{Root: rootB, URL: urlA},
	)
	if _, err := openIndex(t).Rebuild(context.Background(), b); err == nil {
		t.Fatal("Rebuild with colliding ids: expected error")
	}
}

// TestManifestScanIndexRangeRead exercises the whole read-only slice: a manifest
// configures the FS backend, Rebuild indexes the tree, and a byte range of an
// indexed object is read back through the backend.
func TestManifestScanIndexRangeRead(t *testing.T) {
	root := t.TempDir()
	const content = "the quick brown fox"
	writeFile(t, filepath.Join(root, "story.txt"), content)

	manifest, err := json.Marshal([]map[string]string{
		{"root": root, "dataset_resource_url": urlA},
	})
	if err != nil {
		t.Fatal(err)
	}
	datasets, err := storage.ParseManifest(bytes.NewReader(manifest))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	b, err := storage.NewFSBackend(datasets)
	if err != nil {
		t.Fatalf("NewFSBackend: %v", err)
	}

	ix := openIndex(t)
	ctx := context.Background()
	if _, err := ix.Rebuild(ctx, b); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}

	r, err := ix.Get(ctx, storage.ObjectID(urlA, "story.txt"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if r.Size != int64(len(content)) {
		t.Fatalf("size = %d, want %d", r.Size, len(content))
	}

	rsc, err := b.Open(ctx, r.Location)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rsc.Close() }()

	var buf bytes.Buffer
	if _, err := storage.ReadRange(&buf, rsc, r.Size, 4, 5); err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if buf.String() != "quick" {
		t.Fatalf("mid range = %q, want %q", buf.String(), "quick")
	}

	buf.Reset()
	if _, err := storage.ReadRange(&buf, rsc, r.Size, r.Size-3, 3); err != nil {
		t.Fatalf("ReadRange suffix: %v", err)
	}
	if buf.String() != "fox" {
		t.Fatalf("suffix range = %q, want %q", buf.String(), "fox")
	}
}
