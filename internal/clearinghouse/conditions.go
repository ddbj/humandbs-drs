package clearinghouse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ddbj/humandbs-drs/internal/visa"
)

// maxConditionClauses caps both levels of the conditions DNF, so a signed but
// pathological visa cannot make the evaluation arbitrarily expensive.
const maxConditionClauses = 16

// Matcher kinds of a Condition Clause value, the `<match-type>:` prefixes of
// ga4gh_passport_v1 § conditions. An unknown prefix compiles to matcherUnknown,
// which never matches: the clause fails while other OR branches may still
// succeed (spec: "fail to match ... unknown or unsupported").
const (
	matcherConst   = "const"
	matcherPattern = "pattern"
	matcherSplit   = "split_pattern"
	matcherUnknown = "unknown"
)

// conditionMatcher matches one Visa Object claim value.
type conditionMatcher struct {
	kind  string
	value string
}

// conditionClause is one Condition Clause: the required Visa Type plus
// matchers for further claims, all of which must match the same visa.
// Matchers under a claim name outside the string-valued Visa Object claims
// never match, failing the clause.
type conditionClause struct {
	typ      string
	matchers map[string]conditionMatcher
}

// conditionsPresent reports whether a visa carries the conditions claim, with
// JSON null counting as absent. Presence is what excludes a visa from serving
// as a condition match target (architecture.md § "Clearinghouse 設計").
func conditionsPresent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)

	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// compileConditions parses and validates a conditions claim into its DNF. A
// structural violation — not a two-nested list of string-valued objects, an
// empty OR or AND list, a clause without `type` or with nothing besides it, a
// forbidden claim name, a value without a `<match-type>:` prefix, or an
// oversized DNF — is an error, and the visa carrying it must be rejected
// (ga4gh_passport_v1 § conditions).
func compileConditions(raw json.RawMessage) ([][]conditionClause, error) {
	var outer [][]map[string]string
	if err := json.Unmarshal(raw, &outer); err != nil {
		return nil, fmt.Errorf("conditions must be a two-nested list of string-valued objects: %w", err)
	}
	if len(outer) == 0 {
		return nil, fmt.Errorf("conditions has no OR clauses")
	}
	if len(outer) > maxConditionClauses {
		return nil, fmt.Errorf("conditions has %d OR clauses, limit %d", len(outer), maxConditionClauses)
	}

	dnf := make([][]conditionClause, 0, len(outer))
	for i, inner := range outer {
		if len(inner) == 0 {
			return nil, fmt.Errorf("conditions[%d] has no Condition Clauses", i)
		}
		if len(inner) > maxConditionClauses {
			return nil, fmt.Errorf("conditions[%d] has %d Condition Clauses, limit %d", i, len(inner), maxConditionClauses)
		}

		clauses := make([]conditionClause, 0, len(inner))
		for j, rawClause := range inner {
			clause, err := compileClause(rawClause)
			if err != nil {
				return nil, fmt.Errorf("conditions[%d][%d]: %w", i, j, err)
			}
			clauses = append(clauses, clause)
		}
		dnf = append(dnf, clauses)
	}

	return dnf, nil
}

// compileClause validates one Condition Clause: `type` is required and
// implicitly const (no prefix), at least one other claim must be present, and
// claims the spec forbids in conditions (conditions itself and the timestamp
// claims) are rejected.
func compileClause(rawClause map[string]string) (conditionClause, error) {
	typ, ok := rawClause["type"]
	if !ok {
		return conditionClause{}, fmt.Errorf("clause has no type")
	}
	if len(rawClause) < 2 {
		return conditionClause{}, fmt.Errorf("clause needs at least one claim besides type")
	}

	clause := conditionClause{typ: typ, matchers: make(map[string]conditionMatcher, len(rawClause)-1)}
	for key, value := range rawClause {
		if key == "type" {
			continue
		}
		if key == "conditions" || key == "asserted" || key == "exp" {
			return conditionClause{}, fmt.Errorf("clause claim %q is not allowed in conditions", key)
		}

		kind, rest, found := strings.Cut(value, ":")
		if !found {
			return conditionClause{}, fmt.Errorf("clause claim %q value %q has no <match-type>: prefix", key, value)
		}
		switch kind {
		case matcherConst, matcherPattern, matcherSplit:
			clause.matchers[key] = conditionMatcher{kind: kind, value: rest}
		default:
			clause.matchers[key] = conditionMatcher{kind: matcherUnknown}
		}
	}

	return clause, nil
}

// evalConditions reports whether the DNF is satisfied by pool, the same-
// passport verified visas that carry no conditions themselves. The outer level
// is OR, the inner level AND, and every matcher of one clause must match the
// same visa (ga4gh_passport_v1 § conditions).
func evalConditions(dnf [][]conditionClause, pool []visa.Object) bool {
	for _, clauses := range dnf {
		if allClausesMatch(clauses, pool) {
			return true
		}
	}

	return false
}

func allClausesMatch(clauses []conditionClause, pool []visa.Object) bool {
	for _, clause := range clauses {
		if !anyVisaMatches(clause, pool) {
			return false
		}
	}

	return true
}

func anyVisaMatches(clause conditionClause, pool []visa.Object) bool {
	for _, obj := range pool {
		if clauseMatchesVisa(clause, obj) {
			return true
		}
	}

	return false
}

// clauseMatchesVisa reports whether every claim of the clause matches obj. A
// claim the visa does not carry (empty) cannot match, and a claim name outside
// the string-valued Visa Object claims never matches.
func clauseMatchesVisa(clause conditionClause, obj visa.Object) bool {
	if obj.Type != clause.typ {
		return false
	}
	for key, m := range clause.matchers {
		var got string
		switch key {
		case "value":
			got = obj.Value
		case "source":
			got = obj.Source
		case "by":
			got = obj.By
		default:
			return false
		}
		if got == "" || !m.matches(got) {
			return false
		}
	}

	return true
}

func (m conditionMatcher) matches(s string) bool {
	switch m.kind {
	case matcherConst:
		return s == m.value
	case matcherPattern:
		return globMatch(m.value, s)
	case matcherSplit:
		// The visa-side claim value splits on ";"; one matching part suffices.
		for _, part := range strings.Split(s, ";") {
			if globMatch(m.value, part) {
				return true
			}
		}

		return false
	default:
		return false
	}
}
