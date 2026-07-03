package clearinghouse

// globMatch reports whether s matches pattern under the GA4GH Passport
// Pattern Matching rules (ga4gh_passport_v1 § Pattern Matching): the whole
// string must match, comparison is case-sensitive, `?` matches exactly one
// character, `*` matches any run of characters, and there is no escape
// character. Characters are runes, so a multi-byte character counts as one.
//
// The two-pointer walk revisits at most one `*` position per subject rune,
// bounding the work at O(len(pattern) * len(s)) even for adversarial patterns
// like `a*a*a*…`.
func globMatch(pattern, s string) bool {
	p := []rune(pattern)
	t := []rune(s)

	pi, ti := 0, 0
	starPi, starTi := -1, 0
	for ti < len(t) {
		switch {
		// `*` must be recognized before the literal comparison: a literal `*`
		// in the subject would otherwise consume the pattern's wildcard.
		case pi < len(p) && p[pi] == '*':
			// Tentatively match zero runes; remember where to widen.
			starPi, starTi = pi, ti
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case starPi >= 0:
			// Dead end: widen the last `*` by one more rune and retry.
			starTi++
			pi, ti = starPi+1, starTi
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}

	return pi == len(p)
}
