package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// The PBT key space is deliberately small so draws collide: upserts hit
// existing rows, seeds contain duplicate keys, and queries span subjects.
var (
	pbtSubjects = []string{"alice", "bob"}
	pbtDatasets = []string{
		"https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD1",
		"https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD2",
		"https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD3",
	}
	pbtDACs = []string{"https://dac.example.org/a", "https://dac.example.org/b"}
)

type grantKey struct {
	subject string
	dataset string
}

// drawGrant draws a valid grant. Expiries cluster within a few seconds of
// refTime so the expired/active boundary, including exact equality, is hit
// often.
func drawGrant(rt *rapid.T, label string) Grant {
	g := Grant{
		Subject:   rapid.SampledFrom(pbtSubjects).Draw(rt, label+".subject"),
		DatasetID: rapid.SampledFrom(pbtDatasets).Draw(rt, label+".dataset"),
		DACSource: rapid.SampledFrom(pbtDACs).Draw(rt, label+".dac"),
		Asserted:  time.Unix(rapid.Int64Range(refTime.Unix()-1_000_000, refTime.Unix()).Draw(rt, label+".asserted"), 0).UTC(),
	}
	if rapid.Bool().Draw(rt, label+".hasExpires") {
		sec := rapid.Int64Range(refTime.Unix()-5, refTime.Unix()+5).Draw(rt, label+".expires")
		g.Expires = timePtr(time.Unix(sec, 0).UTC())
	}
	if rapid.Bool().Draw(rt, label+".hasConditions") {
		value := rapid.StringMatching(`[a-z]{1,8}`).Draw(rt, label+".condValue")
		g.Conditions = json.RawMessage(fmt.Sprintf(`[[{"type":"AffiliationAndRole","value":%q}]]`, value))
	}

	return g
}

// activeAt mirrors the store's activity rule at its stored second precision:
// no expiry, or an expiry strictly after now.
func activeAt(g Grant, now time.Time) bool {
	return g.Expires == nil || g.Expires.Unix() > now.Unix()
}

// modelGrants returns the model's grants for subject that keep selects, in the
// store's dataset_id order.
func modelGrants(model map[grantKey]Grant, subject string, keep func(Grant) bool) []Grant {
	var grants []Grant
	for key, g := range model {
		if key.subject == subject && keep(g) {
			grants = append(grants, g)
		}
	}
	slices.SortFunc(grants, func(a, b Grant) int { return strings.Compare(a.DatasetID, b.DatasetID) })

	return grants
}

func grantsMatch(got, want []Grant) bool {
	return slices.EqualFunc(got, want, sameGrant)
}

func TestActiveBySubjectMatchesModelFilter(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		offset := rapid.Int64Range(-5, 5).Draw(rt, "nowOffset")
		now := refTime.Add(time.Duration(offset) * time.Second)
		s := newStore(t, fixedClock(now))
		ctx := context.Background()

		model := map[grantKey]Grant{}
		n := rapid.IntRange(0, 10).Draw(rt, "n")
		for i := range n {
			g := drawGrant(rt, fmt.Sprintf("g%d", i))
			if err := s.Put(ctx, g); err != nil {
				rt.Fatalf("Put: %v", err)
			}
			model[grantKey{g.Subject, g.DatasetID}] = g
		}

		for _, subject := range pbtSubjects {
			all, err := s.ListBySubject(ctx, subject)
			if err != nil {
				rt.Fatalf("ListBySubject(%q): %v", subject, err)
			}
			wantAll := modelGrants(model, subject, func(Grant) bool { return true })
			if !grantsMatch(all, wantAll) {
				rt.Fatalf("ListBySubject(%q):\ngot  %+v\nwant %+v", subject, all, wantAll)
			}

			active, err := s.ActiveBySubject(ctx, subject)
			if err != nil {
				rt.Fatalf("ActiveBySubject(%q): %v", subject, err)
			}
			wantActive := modelGrants(model, subject, func(g Grant) bool { return activeAt(g, now) })
			if !grantsMatch(active, wantActive) {
				rt.Fatalf("ActiveBySubject(%q) at %v:\ngot  %+v\nwant %+v", subject, now, active, wantActive)
			}
		}
	})
}

func TestGrantStoreBehavesLikeMapModel(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		s := newStore(t, fixedClock(refTime))
		ctx := context.Background()
		model := map[grantKey]Grant{}

		rt.Repeat(map[string]func(*rapid.T){
			"put": func(rt *rapid.T) {
				g := drawGrant(rt, "put")
				if err := s.Put(ctx, g); err != nil {
					rt.Fatalf("Put: %v", err)
				}
				model[grantKey{g.Subject, g.DatasetID}] = g
			},
			"seed": func(rt *rapid.T) {
				var batch []Grant
				n := rapid.IntRange(1, 3).Draw(rt, "seed.n")
				for i := range n {
					batch = append(batch, drawGrant(rt, fmt.Sprintf("seed.g%d", i)))
				}
				if err := s.Seed(ctx, batch); err != nil {
					rt.Fatalf("Seed: %v", err)
				}
				for _, g := range batch {
					model[grantKey{g.Subject, g.DatasetID}] = g
				}
			},
			"delete": func(rt *rapid.T) {
				key := grantKey{
					subject: rapid.SampledFrom(pbtSubjects).Draw(rt, "delete.subject"),
					dataset: rapid.SampledFrom(pbtDatasets).Draw(rt, "delete.dataset"),
				}
				err := s.Delete(ctx, key.subject, key.dataset)
				if _, ok := model[key]; ok {
					if err != nil {
						rt.Fatalf("Delete existing %v: %v", key, err)
					}
					delete(model, key)
				} else if !errors.Is(err, ErrGrantNotFound) {
					rt.Fatalf("Delete missing %v: error = %v, want ErrGrantNotFound", key, err)
				}
			},
			"get": func(rt *rapid.T) {
				key := grantKey{
					subject: rapid.SampledFrom(pbtSubjects).Draw(rt, "get.subject"),
					dataset: rapid.SampledFrom(pbtDatasets).Draw(rt, "get.dataset"),
				}
				got, err := s.Get(ctx, key.subject, key.dataset)
				want, ok := model[key]
				switch {
				case ok && err != nil:
					rt.Fatalf("Get existing %v: %v", key, err)
				case ok && !sameGrant(got, want):
					rt.Fatalf("Get %v:\ngot  %+v\nwant %+v", key, got, want)
				case !ok && !errors.Is(err, ErrGrantNotFound):
					rt.Fatalf("Get missing %v: error = %v, want ErrGrantNotFound", key, err)
				}
			},
			"": func(rt *rapid.T) {
				for _, subject := range pbtSubjects {
					all, err := s.ListBySubject(ctx, subject)
					if err != nil {
						rt.Fatalf("ListBySubject(%q): %v", subject, err)
					}
					wantAll := modelGrants(model, subject, func(Grant) bool { return true })
					if !grantsMatch(all, wantAll) {
						rt.Fatalf("ListBySubject(%q):\ngot  %+v\nwant %+v", subject, all, wantAll)
					}

					active, err := s.ActiveBySubject(ctx, subject)
					if err != nil {
						rt.Fatalf("ActiveBySubject(%q): %v", subject, err)
					}
					wantActive := modelGrants(model, subject, func(g Grant) bool { return activeAt(g, refTime) })
					if !grantsMatch(active, wantActive) {
						rt.Fatalf("ActiveBySubject(%q):\ngot  %+v\nwant %+v", subject, active, wantActive)
					}
				}
			},
		})
	})
}
