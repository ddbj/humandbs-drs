package clearinghouse

import (
	"regexp"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern string
		s       string
		want    bool
	}{
		{"", "", true},
		{"", "a", false},
		{"a", "", false},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "ABC", false}, // case-sensitive
		{"?", "a", true},
		{"?", "", false},
		{"?", "ab", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"*", "", true},
		{"*", "anything", true},
		{"a*", "a", true},
		{"a*", "abc", true},
		{"a*", "ba", false},
		{"*a", "a", true},
		{"*a", "ba", true},
		{"*a", "ab", false},
		{"a*b*c", "abc", true},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "acb", false},
		{"**", "x", true},
		{"a*a*a*a*b", strings.Repeat("a", 40), false}, // backtracking stress
		// No escape character: '?' and '*' cannot be matched literally via '\'.
		{`\?`, `\a`, true},
		{`\?`, "?", false},
		// '?' consumes one rune, not one byte.
		{"?", "あ", true},
		{"a?c", "aあc", true},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+"/"+tc.s, func(t *testing.T) {
			if got := globMatch(tc.pattern, tc.s); got != tc.want {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
			}
		})
	}
}

// globRegexp translates a glob pattern into an anchored regexp, an independent
// reference implementation for the property test.
func globRegexp(t *rapid.T, pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`\A`)
	for _, r := range pattern {
		switch r {
		case '?':
			b.WriteString(`.`)
		case '*':
			b.WriteString(`(?s:.*)`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString(`\z`)

	re, err := regexp.Compile(b.String())
	if err != nil {
		t.Fatalf("compile reference regexp for %q: %v", pattern, err)
	}

	return re
}

// TestGlobMatchAgainstRegexpReference checks the matcher against a
// regexp-based reference over patterns and subjects drawn from a small
// alphabet (dense in wildcards) plus non-ASCII runes.
func TestGlobMatchAgainstRegexpReference(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		alphabet := []rune{'a', 'b', '?', '*', '.', '+', 'あ'}
		draw := func(label string) string {
			runes := rapid.SliceOfN(rapid.SampledFrom(alphabet), 0, 12).Draw(rt, label)

			return string(runes)
		}

		pattern := draw("pattern")
		s := draw("s")
		got := globMatch(pattern, s)
		want := globRegexp(rt, pattern).MatchString(s)
		if got != want {
			rt.Fatalf("globMatch(%q, %q) = %v, reference = %v", pattern, s, got, want)
		}
	})
}
