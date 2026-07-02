// Package issuer implements the Visa Issuer's server-side state, starting with
// the grant store that backs visa issuance: which subject was granted access to
// which dataset, by which DAC, and until when (architecture.md § "Issuer 設計",
// requirements.md § "Visa Issuer").
package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Errors reported by the grant store. Callers match these with errors.Is to
// distinguish a rejected grant or a missing row from a database failure.
var (
	// ErrInvalidGrant reports a grant that fails validation and was not stored.
	ErrInvalidGrant = errors.New("issuer: invalid grant")
	// ErrGrantNotFound reports a lookup or delete of a grant that does not exist.
	ErrGrantNotFound = errors.New("issuer: grant not found")
)

// Grant records that a DAC granted a subject access to a dataset. It is the row
// shape of the grant DB (architecture.md § "Issuer 設計") and the source material
// for a ControlledAccessGrants visa: DatasetID becomes the visa `value`,
// DACSource its `source`, and Asserted its `asserted` timestamp.
type Grant struct {
	// Subject is the Keycloak subject the grant belongs to.
	Subject string
	// DatasetID is the dataset resource URL the grant covers, matched verbatim
	// against visa `value` (architecture.md § "dataset 識別").
	DatasetID string
	// DACSource is the URL of the DAC that asserted the grant.
	DACSource string
	// Asserted is when the DAC made the assertion.
	Asserted time.Time
	// Expires is when the grant lapses; nil means it never expires. A grant whose
	// Expires is at or before the current time is inactive, matching how visa
	// verification treats `exp`.
	Expires *time.Time
	// Conditions optionally restricts the grant. It is carried verbatim into
	// visa.Object.Conditions; evaluating it is the Clearinghouse's responsibility.
	Conditions json.RawMessage
}

// Validate reports why g cannot be stored: a blank identifying field, a missing
// assertion time, or Conditions that is not valid JSON.
func (g Grant) Validate() error {
	var problems []string
	if g.Subject == "" {
		problems = append(problems, "subject is empty")
	}
	if g.DatasetID == "" {
		problems = append(problems, "dataset_id is empty")
	}
	if g.DACSource == "" {
		problems = append(problems, "dac_source is empty")
	}
	if g.Asserted.IsZero() {
		problems = append(problems, "asserted is zero")
	}
	if g.Conditions != nil && !json.Valid(g.Conditions) {
		problems = append(problems, "conditions is not valid JSON")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidGrant, strings.Join(problems, ", "))
	}

	return nil
}
