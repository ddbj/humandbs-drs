package storage

import (
	"crypto/sha256"
	"encoding/base64"
)

// idSeparator joins the dataset resource URL and the relative path before
// hashing. NUL appears in neither a URL nor a POSIX path, so the concatenation
// is injective: distinct (url, path) pairs never collapse to the same input
// (architecture.md § "object ID scheme").
const idSeparator = "\x00"

// ObjectID derives the canonical, deterministic DRS id of the object at relPath
// within the dataset identified by datasetURL. The id is
// base64url(sha-256(datasetURL + NUL + relPath)) without padding, so it uses only
// unreserved characters ([A-Za-z0-9_-], a subset of [A-Za-z0-9._~-]) and never
// contains '/'. The same inputs always yield the same id, which is what lets a
// filesystem rescan restore ids without any stored state (architecture.md
// § "object ID scheme").
func ObjectID(datasetURL, relPath string) string {
	sum := sha256.Sum256([]byte(datasetURL + idSeparator + relPath))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
