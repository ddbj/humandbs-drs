package storage

import (
	"regexp"
	"testing"

	"pgregory.net/rapid"
)

// unreservedID matches the RFC 3986 unreserved set. A DRS id must stay within it
// so it never needs percent-encoding and never contains '/' (architecture.md
// § "object ID scheme").
var unreservedID = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// drawDatasetInput draws a string from a small NUL-free alphabet, the domain
// ObjectID's separator relies on: dataset URLs (validated NUL-free) and POSIX
// relative paths (which cannot contain NUL). The small alphabet makes near
// collisions like ("ab","c") vs ("a","bc") likely so the separator is exercised.
func drawDatasetInput(rt *rapid.T, label string) string {
	runes := rapid.SliceOfN(
		rapid.RuneFrom([]rune{'a', 'b', 'c', '/', '.', '-', '_', ' ', 'é', '日'}),
		0, 12,
	).Draw(rt, label)

	return string(runes)
}

func TestObjectIDDeterministicAndUnreserved(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		url := rapid.String().Draw(rt, "url")
		rel := rapid.String().Draw(rt, "rel")

		id := ObjectID(url, rel)
		if id != ObjectID(url, rel) {
			rt.Fatalf("ObjectID(%q, %q) not deterministic", url, rel)
		}
		if !unreservedID.MatchString(id) {
			rt.Fatalf("ObjectID(%q, %q) = %q has non-unreserved characters", url, rel, id)
		}
	})
}

// TestObjectIDInjective asserts the biconditional: equal (url, rel) pairs yield
// equal ids (determinism) and distinct pairs yield distinct ids (SHA-256 makes a
// collision practically impossible). It is the property that lets a rescan
// restore ids and keeps two files from sharing one id.
func TestObjectIDInjective(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		url1 := drawDatasetInput(rt, "url1")
		rel1 := drawDatasetInput(rt, "rel1")
		url2 := drawDatasetInput(rt, "url2")
		rel2 := drawDatasetInput(rt, "rel2")

		samePair := url1 == url2 && rel1 == rel2
		sameID := ObjectID(url1, rel1) == ObjectID(url2, rel2)
		if samePair != sameID {
			rt.Fatalf("ObjectID(%q,%q) vs ObjectID(%q,%q): samePair=%v sameID=%v",
				url1, rel1, url2, rel2, samePair, sameID)
		}
	})
}

// TestObjectIDSeparatorPreventsCollision pins the concrete case the NUL separator
// exists for: without it, ("ab","c") and ("a","bc") would hash the same bytes.
func TestObjectIDSeparatorPreventsCollision(t *testing.T) {
	if ObjectID("ab", "c") == ObjectID("a", "bc") {
		t.Fatal("(url, path) concatenation collision: separator does not disambiguate")
	}
}
