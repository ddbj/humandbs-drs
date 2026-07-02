package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Dataset maps one on-disk directory tree to the dataset resource URL its files
// belong to. The filesystem backend is configured with a set of these; each Root
// subtree is one dataset (architecture.md § "storage backend と暗号化").
type Dataset struct {
	// Root is the directory whose files are DRS-ified, pointed at in place.
	Root string `json:"root"`
	// URL is the dataset resource URL every file under Root belongs to, matched
	// verbatim against a visa `value` (architecture.md § "dataset 識別").
	URL string `json:"dataset_resource_url"`
}

// ParseManifest reads the JSON array of datasets that configures the filesystem
// backend: [{"root": "...", "dataset_resource_url": "..."}, ...]. Unknown fields
// and trailing data are rejected so a typo fails loudly. Each dataset's fields are
// validated (present, and a URL free of NUL) so a misconfiguration is caught
// before any scan. Filesystem reality — a root that exists, is a directory, and
// is not nested in another — is checked by NewFSBackend.
func ParseManifest(r io.Reader) ([]Dataset, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var datasets []Dataset
	if err := dec.Decode(&datasets); err != nil {
		return nil, fmt.Errorf("storage: parse manifest: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("storage: parse manifest: trailing data after the dataset array")
	}
	for _, d := range datasets {
		if err := validateDatasetFields(d); err != nil {
			return nil, err
		}
	}

	return datasets, nil
}

// validateDatasetFields checks the invariants of d that do not depend on the
// filesystem: both identifying fields present, and a URL free of the NUL that
// ObjectID relies on being absent to keep ids injective.
func validateDatasetFields(d Dataset) error {
	var problems []string
	if d.Root == "" {
		problems = append(problems, "root is empty")
	}
	if d.URL == "" {
		problems = append(problems, "dataset_resource_url is empty")
	}
	if strings.ContainsRune(d.URL, 0) {
		problems = append(problems, "dataset_resource_url contains NUL")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidManifest, strings.Join(problems, ", "))
	}

	return nil
}
