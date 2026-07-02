package issuer

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// seedEntry is the JSON shape of one grant in a seed file: identifying fields
// verbatim, times as RFC 3339, expires omitted for a non-expiring grant, and
// conditions as the raw GA4GH conditions JSON.
type seedEntry struct {
	Subject    string          `json:"subject"`
	DatasetID  string          `json:"dataset_id"`
	DACSource  string          `json:"dac_source"`
	Asserted   time.Time       `json:"asserted"`
	Expires    *time.Time      `json:"expires,omitempty"`
	Conditions json.RawMessage `json:"conditions,omitempty"`
}

// ParseSeed reads a JSON array of grants, the on-disk format consumed at
// startup and handed to GrantStore.Seed. Unknown fields and trailing data are
// rejected so a typo in a hand-written seed file fails loudly instead of
// silently dropping a field. Semantic validation (blank fields, zero times) is
// GrantStore.Seed's job.
func ParseSeed(r io.Reader) ([]Grant, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var entries []seedEntry
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("issuer: parse seed: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("issuer: parse seed: trailing data after the grant array")
	}

	grants := make([]Grant, len(entries))
	for i, e := range entries {
		grants[i] = Grant(e)
	}

	return grants, nil
}
