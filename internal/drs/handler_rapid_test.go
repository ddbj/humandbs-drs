package drs_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"pgregory.net/rapid"

	"github.com/ddbj/humandbs-drs/internal/drs"
)

// TestObjectShapeProperty generates a random dataset tree, indexes it, and
// checks every object's GET response satisfies the DRS 1.5 invariants and agrees
// with the index record.
func TestObjectShapeProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		count := rapid.IntRange(1, 6).Draw(rt, "files")
		files := make(map[string]string, count)
		for i := 0; i < count; i++ {
			// Each file lives under its own dir so no drawn path turns another
			// file into a directory prefix (which would fail the write, not the
			// handler).
			sub := rapid.StringMatching(`[a-z][a-z0-9]{0,6}(/[a-z][a-z0-9]{0,6}){0,2}`).Draw(rt, "path")
			content := rapid.String().Draw(rt, "content")
			files["d"+strconv.Itoa(i)+"/"+sub] = content
		}

		f := buildFixture(t, files)
		defer f.close()

		for _, id := range f.ids {
			rec := f.records[id]
			resp, err := http.Get(f.url("/objects/" + id))
			if err != nil {
				rt.Fatalf("GET %s: %v", id, err)
			}
			var obj drs.Object
			decodeErr := json.NewDecoder(resp.Body).Decode(&obj)
			_ = resp.Body.Close()
			if decodeErr != nil {
				rt.Fatalf("decode %s: %v", id, decodeErr)
			}

			if want := "drs://drs.example.org/" + id; obj.SelfURI != want {
				rt.Errorf("self_uri = %q, want %q", obj.SelfURI, want)
			}
			if obj.ID != id {
				rt.Errorf("id = %q, want %q", obj.ID, id)
			}
			if obj.Size != rec.Size {
				rt.Errorf("size = %d, want %d", obj.Size, rec.Size)
			}
			if len(obj.Checksums) != 1 || obj.Checksums[0].Type != "sha-256" || obj.Checksums[0].Checksum != rec.SHA256 {
				rt.Errorf("checksums = %+v, want one sha-256 %q", obj.Checksums, rec.SHA256)
			}
			if len(obj.AccessMethods) != 1 || obj.AccessMethods[0].Type != "https" || obj.AccessMethods[0].AccessID != "0" {
				rt.Errorf("access_methods = %+v, want one {https 0}", obj.AccessMethods)
			}
		}
	})
}
