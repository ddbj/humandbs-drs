package drs

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"
)

func TestResolveRangeTable(t *testing.T) {
	cases := []struct {
		name       string
		header     string
		size       int64
		wantResult rangeResult
		wantOffset int64
		wantLength int64
	}{
		{"no header", "", 10, rangeFull, 0, 0},
		{"closed range", "bytes=0-4", 10, rangePartial, 0, 5},
		{"open-ended", "bytes=5-", 10, rangePartial, 5, 5},
		{"suffix", "bytes=-3", 10, rangePartial, 7, 3},
		{"suffix longer than object", "bytes=-100", 10, rangePartial, 0, 10},
		{"end past object clamps", "bytes=2-1000", 10, rangePartial, 2, 8},
		{"single first byte", "bytes=0-0", 10, rangePartial, 0, 1},
		{"single last byte", "bytes=9-9", 10, rangePartial, 9, 1},
		{"whole object explicitly", "bytes=0-9", 10, rangePartial, 0, 10},
		{"start at size", "bytes=10-20", 10, rangeUnsatisfiable, 0, 0},
		{"start past size", "bytes=99-", 10, rangeUnsatisfiable, 0, 0},
		{"zero suffix", "bytes=-0", 10, rangeUnsatisfiable, 0, 0},
		{"range on empty object", "bytes=0-", 0, rangeUnsatisfiable, 0, 0},
		{"suffix on empty object", "bytes=-5", 0, rangeUnsatisfiable, 0, 0},
		{"end before start", "bytes=5-3", 10, rangeFull, 0, 0},
		{"non-numeric", "bytes=abc", 10, rangeFull, 0, 0},
		{"empty spec", "bytes=", 10, rangeFull, 0, 0},
		{"lone dash", "bytes=-", 10, rangeFull, 0, 0},
		{"multiple ranges", "bytes=0-1,3-4", 10, rangeFull, 0, 0},
		{"wrong unit", "items=0-1", 10, rangeFull, 0, 0},
		{"garbage after end", "bytes=1-2-3", 10, rangeFull, 0, 0},
		{"negative-looking start", "bytes=--1", 10, rangeFull, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, offset, length := resolveRange(tc.header, tc.size)
			if res != tc.wantResult || offset != tc.wantOffset || length != tc.wantLength {
				t.Errorf("resolveRange(%q, %d) = (%d, %d, %d), want (%d, %d, %d)",
					tc.header, tc.size, res, offset, length, tc.wantResult, tc.wantOffset, tc.wantLength)
			}
		})
	}
}

// TestResolveRangePartialInvariant is the safety property: whenever a range
// resolves to a partial window, the window lies inside [0, size) and is
// non-empty, so ReadRange never seeks past the object or serves an empty 206.
func TestResolveRangePartialInvariant(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		size := rapid.Int64Range(0, 1000).Draw(rt, "size")
		header := rapid.SampledFrom([]string{
			fmt.Sprintf("bytes=%d-%d", rapid.Int64Range(-5, 1100).Draw(rt, "a"), rapid.Int64Range(-5, 1100).Draw(rt, "b")),
			fmt.Sprintf("bytes=%d-", rapid.Int64Range(-5, 1100).Draw(rt, "start")),
			fmt.Sprintf("bytes=-%d", rapid.Int64Range(-5, 1100).Draw(rt, "suffix")),
		}).Draw(rt, "header")

		res, offset, length := resolveRange(header, size)
		if res != rangePartial {
			return
		}
		if offset < 0 || length < 1 || offset+length > size {
			rt.Errorf("resolveRange(%q, %d) = partial (%d, %d) escapes [0, %d)", header, size, offset, length, size)
		}
	})
}

// TestResolveRangeClosedArithmetic pins the clamp math of a closed range against
// an independent computation, catching off-by-one errors in the end clamp.
func TestResolveRangeClosedArithmetic(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		size := rapid.Int64Range(1, 1000).Draw(rt, "size")
		start := rapid.Int64Range(0, size-1).Draw(rt, "start")
		end := rapid.Int64Range(start, size+50).Draw(rt, "end")

		res, offset, length := resolveRange(fmt.Sprintf("bytes=%d-%d", start, end), size)
		wantEnd := min(end, size-1)
		if res != rangePartial || offset != start || length != wantEnd-start+1 {
			rt.Errorf("resolveRange(bytes=%d-%d, %d) = (%d, %d, %d), want partial start=%d len=%d",
				start, end, size, res, offset, length, start, wantEnd-start+1)
		}
	})
}

// TestResolveRangeSuffixArithmetic pins that a suffix range always ends at the
// last byte and never asks for more than the object holds.
func TestResolveRangeSuffixArithmetic(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		size := rapid.Int64Range(1, 1000).Draw(rt, "size")
		suffix := rapid.Int64Range(1, size+50).Draw(rt, "suffix")

		res, offset, length := resolveRange(fmt.Sprintf("bytes=-%d", suffix), size)
		wantLen := min(suffix, size)
		if res != rangePartial || length != wantLen || offset+length != size {
			rt.Errorf("resolveRange(bytes=-%d, %d) = (%d, %d, %d), want partial len=%d ending at %d",
				suffix, size, res, offset, length, wantLen, size)
		}
	})
}
