package clearinghouse

import (
	"encoding/json"
	"testing"

	"pgregory.net/rapid"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

func TestConditionsPresent(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{"absent", nil, false},
		{"empty", json.RawMessage(""), false},
		{"null", json.RawMessage("null"), false},
		{"null with space", json.RawMessage(" null "), false},
		{"empty array", json.RawMessage("[]"), true},
		{"object", json.RawMessage(`[[{"type":"x","by":"const:dac"}]]`), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := conditionsPresent(tc.raw); got != tc.want {
				t.Errorf("conditionsPresent(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestCompileConditionsRejectsStructuralViolations(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"not an array", `{"type":"x"}`},
		{"flat array", `[{"type":"x","by":"const:dac"}]`},
		{"empty outer", `[]`},
		{"empty inner", `[[]]`},
		{"empty clause", `[[{}]]`},
		{"missing type", `[[{"by":"const:dac"}]]`},
		{"type only", `[[{"type":"AffiliationAndRole"}]]`},
		{"non-string value", `[[{"type":"x","by":123}]]`},
		{"no match-type prefix", `[[{"type":"x","by":"dac"}]]`},
		{"condition on conditions", `[[{"type":"x","conditions":"const:y"}]]`},
		{"condition on asserted", `[[{"type":"x","asserted":"const:1"}]]`},
		{"condition on exp", `[[{"type":"x","exp":"const:1"}]]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileConditions(json.RawMessage(tc.raw)); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestCompileConditionsCapsClauseCounts(t *testing.T) {
	clause := `{"type":"x","by":"const:dac"}`

	wide := "["
	for range maxConditionClauses + 1 {
		wide += `[` + clause + `],`
	}
	wide = wide[:len(wide)-1] + "]"
	if _, err := compileConditions(json.RawMessage(wide)); err == nil {
		t.Error("want error for too many OR clauses, got nil")
	}

	deep := "[["
	for range maxConditionClauses + 1 {
		deep += clause + `,`
	}
	deep = deep[:len(deep)-1] + "]]"
	if _, err := compileConditions(json.RawMessage(deep)); err == nil {
		t.Error("want error for too many AND clauses, got nil")
	}
}

// TestCompileConditionsToleratesUnknownMatchersAndClaims pins that an unknown
// match-type prefix or an unknown (but string-valued, non-timestamp) claim
// name compiles: per spec it fails the clause at evaluation, without
// invalidating the visa.
func TestCompileConditionsToleratesUnknownMatchersAndClaims(t *testing.T) {
	raw := json.RawMessage(`[[{"type":"x","by":"fancy_match:dac"}],[{"type":"x","futureclaim":"const:y"}]]`)
	dnf, err := compileConditions(raw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if evalConditions(dnf, []visa.Object{{Type: "x", By: "dac", Value: "y", Source: "s"}}) {
		t.Error("clauses with unknown prefixes or claims must not match")
	}
}

// affiliation returns an AffiliationAndRole visa object, the spec's canonical
// condition target.
func affiliation(value, source, by string) visa.Object {
	return visa.Object{Type: "AffiliationAndRole", Asserted: 1, Value: value, Source: source, By: by}
}

func mustCompile(t *testing.T, raw string) [][]conditionClause {
	t.Helper()

	dnf, err := compileConditions(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("compile %s: %v", raw, err)
	}

	return dnf
}

func TestEvalConditions(t *testing.T) {
	pool := []visa.Object{
		affiliation("faculty@med.stanford.edu", "https://grid.ac/institutes/grid.240952.8", "so"),
		{Type: "ResearcherStatus", Asserted: 1, Value: "https://doi.org/10.1", Source: "https://grid.ac/institutes/grid.240952.8", By: "system"},
	}

	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{
			"const match on value and source",
			`[[{"type":"AffiliationAndRole","value":"const:faculty@med.stanford.edu","source":"const:https://grid.ac/institutes/grid.240952.8"}]]`,
			true,
		},
		{
			"const mismatch on value",
			`[[{"type":"AffiliationAndRole","value":"const:student@med.stanford.edu"}]]`,
			false,
		},
		{
			"const is case-sensitive",
			`[[{"type":"AffiliationAndRole","value":"const:Faculty@med.stanford.edu"}]]`,
			false,
		},
		{
			"type mismatch",
			`[[{"type":"AcceptedTermsAndPolicies","value":"const:faculty@med.stanford.edu"}]]`,
			false,
		},
		{
			"pattern match",
			`[[{"type":"AffiliationAndRole","value":"pattern:faculty@*.stanford.edu"}]]`,
			true,
		},
		{
			"pattern must cover the full string",
			`[[{"type":"AffiliationAndRole","value":"pattern:faculty@*.stanford"}]]`,
			false,
		},
		{
			"by match",
			`[[{"type":"AffiliationAndRole","by":"const:so"}]]`,
			true,
		},
		{
			"by mismatch",
			`[[{"type":"AffiliationAndRole","by":"const:self"}]]`,
			false,
		},
		{
			"AND across claims must hit the same visa",
			`[[{"type":"AffiliationAndRole","value":"const:faculty@med.stanford.edu","by":"const:system"}]]`,
			false, // value matches the affiliation visa, by only the status visa
		},
		{
			"AND across clauses may hit different visas",
			`[[{"type":"AffiliationAndRole","by":"const:so"},{"type":"ResearcherStatus","by":"const:system"}]]`,
			true,
		},
		{
			"AND fails when one clause fails",
			`[[{"type":"AffiliationAndRole","by":"const:so"},{"type":"ResearcherStatus","by":"const:dac"}]]`,
			false,
		},
		{
			"OR succeeds via the second branch",
			`[[{"type":"AffiliationAndRole","by":"const:self"}],[{"type":"ResearcherStatus","by":"const:system"}]]`,
			true,
		},
		{
			"unknown prefix fails its branch but not the other",
			`[[{"type":"AffiliationAndRole","by":"fancy_match:so"}],[{"type":"AffiliationAndRole","by":"const:so"}]]`,
			true,
		},
		{
			"unknown claim key fails its branch but not the other",
			`[[{"type":"AffiliationAndRole","futureclaim":"const:x"}],[{"type":"AffiliationAndRole","by":"const:so"}]]`,
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalConditions(mustCompile(t, tc.raw), pool); got != tc.want {
				t.Errorf("evalConditions = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEvalConditionsSplitPattern is the spec's split_pattern example
// (ga4gh_passport_v1 § conditions): the visa-side claim value splits on ";"
// and one part matching the pattern suffices. The prefix is cut at the first
// ":", so the pattern itself may contain ":".
func TestEvalConditionsSplitPattern(t *testing.T) {
	pool := []visa.Object{{
		Type:     "LinkedIdentities",
		Asserted: 1,
		Value:    "001,https:%2F%2Fexample1.org;123,https:%2F%2Fexample2.org;456,https:%2F%2Fexample3.org",
		Source:   "https://example.org",
	}}

	match := `[[{"type":"LinkedIdentities","value":"split_pattern:123,https:%2F%2Fexample?.org"}]]`
	if !evalConditions(mustCompile(t, match), pool) {
		t.Error("split_pattern must match one of the split parts")
	}

	// The same value as a plain pattern must fail: no single part is the
	// whole string.
	whole := `[[{"type":"LinkedIdentities","value":"pattern:123,https:%2F%2Fexample?.org"}]]`
	if evalConditions(mustCompile(t, whole), pool) {
		t.Error("pattern over the unsplit value must not match")
	}
}

// TestEvalConditionsAbsentClaimCannotMatch pins that a clause naming a claim
// the visa does not carry fails, whatever the matcher.
func TestEvalConditionsAbsentClaimCannotMatch(t *testing.T) {
	pool := []visa.Object{affiliation("faculty@x", "https://x", "")}

	for _, raw := range []string{
		`[[{"type":"AffiliationAndRole","by":"const:"}]]`,
		`[[{"type":"AffiliationAndRole","by":"pattern:*"}]]`,
	} {
		if evalConditions(mustCompile(t, raw), pool) {
			t.Errorf("%s matched a visa without a by claim", raw)
		}
	}
}

func TestEvalConditionsEmptyPool(t *testing.T) {
	dnf := mustCompile(t, `[[{"type":"AffiliationAndRole","by":"const:so"}]]`)
	if evalConditions(dnf, nil) {
		t.Error("no pool visa can satisfy a condition")
	}
}

// TestEvalConditionsDNFProperty checks the OR-of-ANDs logic against a randomly
// drawn truth assignment: each clause is constructed to be definitely true
// (const-matching a pool visa) or definitely false (a type absent from the
// pool), so the expected result is computable independently of the matcher.
func TestEvalConditionsDNFProperty(t *testing.T) {
	pool := []visa.Object{
		affiliation("faculty@a.example", "https://a.example", "so"),
		{Type: "ResearcherStatus", Asserted: 1, Value: "https://doi.org/10.1", Source: "https://b.example", By: "system"},
	}
	trueClauses := []string{
		`{"type":"AffiliationAndRole","value":"const:faculty@a.example"}`,
		`{"type":"ResearcherStatus","by":"const:system"}`,
		`{"type":"AffiliationAndRole","source":"pattern:https://?.example"}`,
	}
	falseClauses := []string{
		`{"type":"AcceptedTermsAndPolicies","value":"const:faculty@a.example"}`,
		`{"type":"AffiliationAndRole","value":"const:student@a.example"}`,
		`{"type":"ResearcherStatus","by":"unknown_match:system"}`,
	}

	rapid.Check(t, func(rt *rapid.T) {
		orCount := rapid.IntRange(1, 4).Draw(rt, "orCount")
		want := false
		raw := "["
		for i := range orCount {
			andCount := rapid.IntRange(1, 4).Draw(rt, "andCount")
			branchTrue := true
			raw += "["
			for j := range andCount {
				clauseTrue := rapid.Bool().Draw(rt, "clause")
				branchTrue = branchTrue && clauseTrue
				var clause string
				if clauseTrue {
					clause = rapid.SampledFrom(trueClauses).Draw(rt, "trueClause")
				} else {
					clause = rapid.SampledFrom(falseClauses).Draw(rt, "falseClause")
				}
				raw += clause
				if j < andCount-1 {
					raw += ","
				}
			}
			raw += "]"
			if i < orCount-1 {
				raw += ","
			}
			want = want || branchTrue
		}
		raw += "]"

		dnf, err := compileConditions(json.RawMessage(raw))
		if err != nil {
			rt.Fatalf("compile %s: %v", raw, err)
		}
		if got := evalConditions(dnf, pool); got != want {
			rt.Fatalf("evalConditions(%s) = %v, want %v", raw, got, want)
		}
	})
}
