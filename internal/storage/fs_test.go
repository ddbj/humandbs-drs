package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const (
	urlA = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001"
	urlB = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000002"
)

// writeFile writes content to path, creating parent directories. It is the
// real-file fixture the FS backend tests scan; the FS boundary is exercised
// directly rather than mocked.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFSBackendScan(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()

	writeFile(t, filepath.Join(rootA, "a.txt"), "aaa")
	writeFile(t, filepath.Join(rootA, "sub", "b.txt"), "bbbb")
	writeFile(t, filepath.Join(rootA, "empty"), "")
	writeFile(t, filepath.Join(rootA, ".hidden"), "secret")
	writeFile(t, filepath.Join(rootA, ".git", "config"), "vcs")
	writeFile(t, filepath.Join(rootB, "c.txt"), "cc")

	if err := os.Symlink(filepath.Join(rootA, "a.txt"), filepath.Join(rootA, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(rootA, "sub"), filepath.Join(rootA, "linkdir")); err != nil {
		t.Fatal(err)
	}

	b, err := NewFSBackend([]Dataset{{Root: rootA, URL: urlA}, {Root: rootB, URL: urlB}})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]Entry{}
	err = b.Scan(context.Background(), func(e Entry) error {
		if _, dup := got[e.ID]; dup {
			t.Fatalf("duplicate id %q", e.ID)
		}
		got[e.ID] = e

		return nil
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want := []struct {
		url, rel string
		size     int64
	}{
		{urlA, "a.txt", 3},
		{urlA, "sub/b.txt", 4},
		{urlA, "empty", 0},
		{urlB, "c.txt", 2},
	}
	if len(got) != len(want) {
		t.Fatalf("scanned %d objects, want %d (dotfiles, dot-dirs, and symlinks excluded): %+v",
			len(got), len(want), got)
	}
	for _, w := range want {
		id := ObjectID(w.url, w.rel)
		e, ok := got[id]
		if !ok {
			t.Fatalf("missing object for (%q, %q)", w.url, w.rel)
		}
		if e.DatasetURL != w.url {
			t.Fatalf("object (%q, %q): dataset = %q, want %q", w.url, w.rel, e.DatasetURL, w.url)
		}
		if e.Size != w.size {
			t.Fatalf("object (%q, %q): size = %d, want %d", w.url, w.rel, e.Size, w.size)
		}
		if e.ModTime.IsZero() {
			t.Fatalf("object (%q, %q): ModTime is zero", w.url, w.rel)
		}
	}
}

func TestFSBackendScanEmptyDir(t *testing.T) {
	b, err := NewFSBackend([]Dataset{{Root: t.TempDir(), URL: urlA}})
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	if err := b.Scan(context.Background(), func(Entry) error { count++; return nil }); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if count != 0 {
		t.Fatalf("empty dir scanned %d objects, want 0", count)
	}
}

func TestFSBackendScanStopsOnVisitError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a"), "1")
	writeFile(t, filepath.Join(root, "b"), "2")
	b, err := NewFSBackend([]Dataset{{Root: root, URL: urlA}})
	if err != nil {
		t.Fatal(err)
	}

	stop := errors.New("stop")
	seen := 0
	err = b.Scan(context.Background(), func(Entry) error {
		seen++

		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("Scan error = %v, want stop", err)
	}
	if seen != 1 {
		t.Fatalf("visited %d entries before stopping, want 1", seen)
	}
}

func TestFSBackendOpenReadsBytes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "data.txt"), "hello world")
	b, err := NewFSBackend([]Dataset{{Root: root, URL: urlA}})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	var loc string
	if err := b.Scan(ctx, func(e Entry) error { loc = e.Location; return nil }); err != nil {
		t.Fatal(err)
	}

	rsc, err := b.Open(ctx, loc)
	if err != nil {
		t.Fatalf("Open(%q): %v", loc, err)
	}
	defer func() { _ = rsc.Close() }()

	got, err := io.ReadAll(rsc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("read %q, want %q", got, "hello world")
	}
}

func TestFSBackendOpenRejectsEscape(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "in.txt"), "x")
	b, err := NewFSBackend([]Dataset{{Root: root, URL: urlA}})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for _, bad := range []string{
		filepath.Join(root, "..", "outside.txt"),
		filepath.Join(root, "sub", "..", "..", "escape"),
		"/etc/passwd",
	} {
		if _, err := b.Open(ctx, bad); !errors.Is(err, ErrLocationOutsideRoot) {
			t.Fatalf("Open(%q): error = %v, want ErrLocationOutsideRoot", bad, err)
		}
	}
}
