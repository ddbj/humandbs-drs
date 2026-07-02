package issuer

import (
	"strings"
	"testing"
	"time"
)

func TestParseSeedFullAndMinimalEntries(t *testing.T) {
	const input = `[
		{
			"subject": "alice",
			"dataset_id": "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1",
			"dac_source": "https://dac.example.org/a",
			"asserted": "2023-11-14T22:13:20Z",
			"expires": "2023-11-15T22:13:20Z",
			"conditions": [[{"type":"AffiliationAndRole","value":"faculty@example.org"}]]
		},
		{
			"subject": "bob",
			"dataset_id": "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD2",
			"dac_source": "https://dac.example.org/b",
			"asserted": "2023-11-14T22:13:20Z"
		}
	]`

	grants, err := ParseSeed(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSeed: %v", err)
	}
	if len(grants) != 2 {
		t.Fatalf("len(grants) = %d, want 2", len(grants))
	}

	full := grants[0]
	if full.Subject != "alice" || full.DatasetID != "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1" {
		t.Errorf("full grant identity = %q/%q", full.Subject, full.DatasetID)
	}
	if want := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC); !full.Asserted.Equal(want) {
		t.Errorf("asserted = %s, want %s", full.Asserted, want)
	}
	if full.Expires == nil || !full.Expires.Equal(time.Date(2023, 11, 15, 22, 13, 20, 0, time.UTC)) {
		t.Errorf("expires = %v, want 2023-11-15T22:13:20Z", full.Expires)
	}
	if !strings.Contains(string(full.Conditions), "AffiliationAndRole") {
		t.Errorf("conditions = %s, want the raw conditions JSON", full.Conditions)
	}

	minimal := grants[1]
	if minimal.Expires != nil {
		t.Errorf("expires = %v, want nil for an omitted expires", minimal.Expires)
	}
	if minimal.Conditions != nil {
		t.Errorf("conditions = %s, want nil for omitted conditions", minimal.Conditions)
	}
}

func TestParseSeedAcceptsTimezoneOffsets(t *testing.T) {
	const input = `[{
		"subject": "alice",
		"dataset_id": "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1",
		"dac_source": "https://dac.example.org/a",
		"asserted": "2023-11-15T07:13:20+09:00"
	}]`

	grants, err := ParseSeed(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSeed: %v", err)
	}
	if want := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC); !grants[0].Asserted.Equal(want) {
		t.Errorf("asserted = %s, want the same instant as %s", grants[0].Asserted, want)
	}
}

func TestParseSeedEmptyArray(t *testing.T) {
	grants, err := ParseSeed(strings.NewReader(`[]`))
	if err != nil {
		t.Fatalf("ParseSeed: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("len(grants) = %d, want 0", len(grants))
	}
}

func TestParseSeedRejectsBadInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"not json", "not json"},
		{"object instead of array", `{"subject":"alice"}`},
		{"unknown field", `[{"subject":"alice","dataset":"typo-field"}]`},
		{"non-rfc3339 time", `[{"subject":"alice","dataset_id":"d","dac_source":"s","asserted":"2023/11/14"}]`},
		{"trailing data", `[] "extra"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseSeed(strings.NewReader(tt.input)); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}
