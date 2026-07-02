package storage

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FSBackend DRS-ifies existing directories read-only: it walks each configured
// dataset root and turns every regular file into a DRS object with a deterministic
// id, without moving or modifying the tree (architecture.md § "storage backend と
// 暗号化").
type FSBackend struct {
	datasets []resolvedDataset
}

// resolvedDataset is a Dataset whose Root has been resolved to an absolute,
// symlink-free directory, so a scan starts at the real tree and Open can check
// containment against it.
type resolvedDataset struct {
	root string
	url  string
}

// NewFSBackend resolves each dataset root to a real directory and returns a
// backend over them. It rejects a field-invalid dataset, a root that is missing
// or not a directory, and a root nested inside another (which would expose one
// file as two datasets). Roots are resolved through symlinks so a symlinked root
// is still walked, while symlinks inside a tree are skipped by Scan.
func NewFSBackend(datasets []Dataset) (*FSBackend, error) {
	resolved := make([]resolvedDataset, 0, len(datasets))
	for _, d := range datasets {
		if err := validateDatasetFields(d); err != nil {
			return nil, err
		}
		root, err := resolveDir(d.Root)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, resolvedDataset{root: root, url: d.URL})
	}
	if err := checkNoNestedRoots(resolved); err != nil {
		return nil, err
	}

	return &FSBackend{datasets: resolved}, nil
}

// Scan walks each dataset root and calls visit for every regular file, assigning
// it a deterministic id. It skips symlinks (which could escape the tree), dotfiles
// and dot-directories (system and VCS metadata), and any non-regular file, so only
// real payload becomes an object. An empty file is a zero-byte object.
func (b *FSBackend) Scan(ctx context.Context, visit func(Entry) error) error {
	for _, d := range b.datasets {
		if err := scanRoot(ctx, d, visit); err != nil {
			return err
		}
	}

	return nil
}

func scanRoot(ctx context.Context, d resolvedDataset, visit func(Entry) error) error {
	walkErr := filepath.WalkDir(d.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		if path != d.root && strings.HasPrefix(entry.Name(), ".") {
			if entry.IsDir() {
				return fs.SkipDir
			}

			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("storage: stat %q: %w", path, err)
		}
		rel, err := filepath.Rel(d.root, path)
		if err != nil {
			return fmt.Errorf("storage: relativize %q: %w", path, err)
		}

		return visit(Entry{
			ID:         ObjectID(d.url, filepath.ToSlash(rel)),
			DatasetURL: d.url,
			Location:   path,
			Size:       info.Size(),
			ModTime:    info.ModTime(),
		})
	})
	if walkErr != nil {
		return fmt.Errorf("storage: scan %q: %w", d.url, walkErr)
	}

	return nil
}

// Open opens the object bytes at loc. loc must be a path the backend produced;
// Open rejects one that escapes every dataset root, so a stale or tampered index
// cannot read arbitrary files through the backend (ErrLocationOutsideRoot).
// Containment is checked lexically; symlinks were already skipped at scan time.
func (b *FSBackend) Open(ctx context.Context, loc string) (io.ReadSeekCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	clean := filepath.Clean(loc)
	if !b.contains(clean) {
		return nil, fmt.Errorf("%w: %q", ErrLocationOutsideRoot, loc)
	}

	f, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("storage: open %q: %w", loc, err)
	}

	return f, nil
}

// contains reports whether cleaned path lies within any configured dataset root.
func (b *FSBackend) contains(path string) bool {
	for _, d := range b.datasets {
		if within(path, d.root) {
			return true
		}
	}

	return false
}

// resolveDir resolves dir to an absolute, symlink-free path and confirms it is an
// existing directory.
func resolveDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("storage: resolve root %q: %w", dir, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("storage: resolve root %q: %w", dir, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("storage: resolve root %q: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: root %q is not a directory", ErrInvalidManifest, dir)
	}

	return resolved, nil
}

// checkNoNestedRoots rejects a configured root that is, or lies inside, another.
// Two datasets sharing a subtree would list the same file under both, which the
// deterministic ids allow but the configuration almost never intends.
func checkNoNestedRoots(datasets []resolvedDataset) error {
	for i := range datasets {
		for j := range datasets {
			if i != j && within(datasets[i].root, datasets[j].root) {
				return fmt.Errorf("%w: root %q is nested in root %q",
					ErrInvalidManifest, datasets[i].root, datasets[j].root)
			}
		}
	}

	return nil
}

// within reports whether path is parent or lies inside parent, comparing cleaned
// absolute paths. A path that resolves to ".." or steps above parent is outside.
func within(path, parent string) bool {
	rel, err := filepath.Rel(parent, path)
	if err != nil {
		return false
	}

	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
