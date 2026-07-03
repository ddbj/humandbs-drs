package drs_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ddbj/humandbs-drs/internal/drs"
)

// get is a GET /data/{id} shorthand.
func (f *fixture) get(t *testing.T, id, bearer string, headers map[string]string) httpResult {
	t.Helper()

	return f.fetchData(t, http.MethodGet, id, bearer, headers)
}

// postRevoke POSTs a JSON body to the admin revoke endpoint with the given
// bearer token and returns the drained result.
func (f *fixture) postRevoke(t *testing.T, bearer string, body any) httpResult {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, f.adminRevokeURL(), bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	return do(t, req)
}

// revokedCount unmarshals the {"revoked": n} body of an admin revoke response.
func revokedCount(t *testing.T, res httpResult) int {
	t.Helper()
	var body struct {
		Revoked int `json:"revoked"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		t.Fatalf("decode revoke body %q: %v", res.body, err)
	}

	return body.Revoked
}

func TestDataFullDownload(t *testing.T) {
	const content = "hello world"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.get(t, id, tok, nil)
	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.status)
	}
	if got := res.header.Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("Accept-Ranges = %q, want bytes", got)
	}
	if got := res.header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", got)
	}
	if got := res.header.Get("Content-Disposition"); got != "attachment" {
		t.Errorf("Content-Disposition = %q, want attachment", got)
	}
	if res.header.Get("ETag") == "" {
		t.Error("missing ETag")
	}
	if res.header.Get("Last-Modified") == "" {
		t.Error("missing Last-Modified")
	}
	if got := res.header.Get("Content-Length"); got != strconv.Itoa(len(content)) {
		t.Errorf("Content-Length = %q, want %d", got, len(content))
	}
	if string(res.body) != content {
		t.Errorf("body = %q, want %q", res.body, content)
	}
}

func TestDataHeadSendsNoBody(t *testing.T) {
	const content = "hello world"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.fetchData(t, http.MethodHead, id, tok, nil)
	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.status)
	}
	if got := res.header.Get("Content-Length"); got != strconv.Itoa(len(content)) {
		t.Errorf("Content-Length = %q, want %d", got, len(content))
	}
	if len(res.body) != 0 {
		t.Errorf("HEAD body = %q, want empty", res.body)
	}
}

func TestDataClosedRange(t *testing.T) {
	const content = "abcdefghij"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.get(t, id, tok, map[string]string{"Range": "bytes=2-5"})
	if res.status != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", res.status)
	}
	if got, want := res.header.Get("Content-Range"), "bytes 2-5/10"; got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
	if string(res.body) != content[2:6] {
		t.Errorf("body = %q, want %q", res.body, content[2:6])
	}
}

func TestDataSuffixRange(t *testing.T) {
	const content = "abcdefghij"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.get(t, id, tok, map[string]string{"Range": "bytes=-3"})
	if res.status != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", res.status)
	}
	if got, want := res.header.Get("Content-Range"), "bytes 7-9/10"; got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
	if string(res.body) != content[7:] {
		t.Errorf("body = %q, want %q", res.body, content[7:])
	}
}

func TestDataOpenEndedRange(t *testing.T) {
	const content = "abcdefghij"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.get(t, id, tok, map[string]string{"Range": "bytes=6-"})
	if res.status != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", res.status)
	}
	if string(res.body) != content[6:] {
		t.Errorf("body = %q, want %q", res.body, content[6:])
	}
}

func TestDataUnsatisfiableRange(t *testing.T) {
	const content = "abcdefghij"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.get(t, id, tok, map[string]string{"Range": "bytes=100-200"})
	if res.status != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want 416", res.status)
	}
	if got, want := res.header.Get("Content-Range"), "bytes */10"; got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
	if len(res.body) != 0 {
		t.Errorf("416 body = %q, want empty", res.body)
	}
}

// TestDataZeroByteObject pins the empty-object edges: a plain GET is 200 with an
// empty body, and any range is unsatisfiable.
func TestDataZeroByteObject(t *testing.T) {
	f := newFixture(t, map[string]string{"empty.dat": ""})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	full := f.get(t, id, tok, nil)
	if full.status != http.StatusOK {
		t.Fatalf("full status = %d, want 200", full.status)
	}
	if len(full.body) != 0 {
		t.Errorf("body = %q, want empty", full.body)
	}

	ranged := f.get(t, id, tok, map[string]string{"Range": "bytes=0-"})
	if ranged.status != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("range status = %d, want 416", ranged.status)
	}
	if got, want := ranged.header.Get("Content-Range"), "bytes */0"; got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
}

// TestDataMalformedOrMultiRangeServesFull pins that a range this server does not
// serve as partial falls back to the whole object (RFC 7233 permits it).
func TestDataMalformedOrMultiRangeServesFull(t *testing.T) {
	const content = "abcdefghij"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	for _, hdr := range []string{"bytes=abc", "bytes=5-3", "items=0-1", "bytes=0-1,3-4"} {
		t.Run(hdr, func(t *testing.T) {
			res := f.get(t, id, tok, map[string]string{"Range": hdr})
			if res.status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (full)", res.status)
			}
			if string(res.body) != content {
				t.Errorf("body = %q, want full %q", res.body, content)
			}
		})
	}
}

func TestDataMissingTokenIsUnauthorized(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})
	id := f.ids[0]

	res := f.get(t, id, "", nil)
	if res.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.status)
	}
	if res.header.Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

func TestDataUnknownTokenIsUnauthorized(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})
	id := f.ids[0]

	res := f.get(t, id, "never-issued-token", nil)
	if res.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.status)
	}
}

// TestDataWrongObjectTokenIsForbidden pins that a token issued for one object
// cannot fetch another: 403, not 401, so the client knows the credential is real
// but not for this resource.
func TestDataWrongObjectTokenIsForbidden(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa", "b.txt": "bbb"})
	if len(f.ids) != 2 {
		t.Fatalf("expected two objects, got %d", len(f.ids))
	}
	tok := f.accessToken(t, f.ids[0])

	res := f.get(t, f.ids[1], tok, nil)
	if res.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.status)
	}
}

func TestDataNotModifiedByETag(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "hello"})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	etag := f.get(t, id, tok, nil).header.Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag on first response")
	}

	res := f.get(t, id, tok, map[string]string{"If-None-Match": etag})
	if res.status != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", res.status)
	}
	if len(res.body) != 0 {
		t.Errorf("304 body = %q, want empty", res.body)
	}
}

func TestDataNotModifiedByIfModifiedSince(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "hello"})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	lastMod := f.get(t, id, tok, nil).header.Get("Last-Modified")
	if lastMod == "" {
		t.Fatal("missing Last-Modified on first response")
	}

	res := f.get(t, id, tok, map[string]string{"If-Modified-Since": lastMod})
	if res.status != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", res.status)
	}
}

func TestDataIfRangeMatchHonorsRange(t *testing.T) {
	const content = "abcdefghij"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	etag := f.get(t, id, tok, nil).header.Get("ETag")

	res := f.get(t, id, tok, map[string]string{"If-Range": etag, "Range": "bytes=0-3"})
	if res.status != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", res.status)
	}
	if string(res.body) != content[0:4] {
		t.Errorf("body = %q, want %q", res.body, content[0:4])
	}
}

// TestDataIfRangeMismatchServesFull pins that a stale If-Range validator yields
// the whole current object, not a range of it.
func TestDataIfRangeMismatchServesFull(t *testing.T) {
	const content = "abcdefghij"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.get(t, id, tok, map[string]string{"If-Range": `"sha256:stale"`, "Range": "bytes=0-3"})
	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (full)", res.status)
	}
	if string(res.body) != content {
		t.Errorf("body = %q, want full %q", res.body, content)
	}
}

// TestRevokeStopsDeliveryImmediately is the § 4.7 guarantee: after an admin
// revokes the (subject, dataset), the same token is refused on the next request.
func TestRevokeStopsDeliveryImmediately(t *testing.T) {
	const content = "hello world"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	if before := f.get(t, id, tok, nil); before.status != http.StatusOK {
		t.Fatalf("before revoke: status = %d, want 200", before.status)
	}

	res := f.postRevoke(t, testAdminToken, map[string]string{"subject": testSubject, "dataset": datasetURL})
	if res.status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", res.status)
	}
	if n := revokedCount(t, res); n != 1 {
		t.Errorf("revoked = %d, want 1", n)
	}

	if after := f.get(t, id, tok, nil); after.status != http.StatusUnauthorized {
		t.Fatalf("after revoke: status = %d, want 401", after.status)
	}
}

// TestRevokeNonMatchingDatasetKeepsDelivery pins revoke precision: revoking the
// subject for a different dataset leaves this dataset's session working.
func TestRevokeNonMatchingDatasetKeepsDelivery(t *testing.T) {
	const content = "hello world"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.postRevoke(t, testAdminToken, map[string]string{
		"subject": testSubject,
		"dataset": "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD999999",
	})
	if n := revokedCount(t, res); n != 0 {
		t.Errorf("revoked = %d, want 0 for a non-matching dataset", n)
	}

	if after := f.get(t, id, tok, nil); after.status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (session kept)", after.status)
	}
}

func TestRevokeRejectsBadAdminAuth(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})

	for name, bearer := range map[string]string{"no token": "", "wrong token": "not-the-secret"} {
		t.Run(name, func(t *testing.T) {
			res := f.postRevoke(t, bearer, map[string]string{"subject": testSubject, "dataset": datasetURL})
			if res.status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", res.status)
			}
		})
	}
}

func TestRevokeRequiresSubject(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})

	res := f.postRevoke(t, testAdminToken, map[string]string{"dataset": datasetURL})
	if res.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.status)
	}
}

func TestRevokeRejectsMalformedBody(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})

	req, err := http.NewRequest(http.MethodPost, f.adminRevokeURL(), strings.NewReader("{not json"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	if res := do(t, req); res.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.status)
	}
}

// TestRevokeDisabledWithoutAdminToken pins the fail-closed default: with no admin
// secret configured the endpoint refuses to revoke rather than allowing it.
func TestRevokeDisabledWithoutAdminToken(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"}, func(s *drs.Settings) {
		s.AdminToken = ""
	})

	res := f.postRevoke(t, "anything", map[string]string{"subject": testSubject, "dataset": datasetURL})
	if res.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", res.status)
	}
}

// TestDataRoundTripMatchesObject ties the flow together: the delivered bytes
// hash to the object's advertised checksum, so authorization, the session token,
// and the byte path agree on the same object.
func TestDataRoundTripMatchesObject(t *testing.T) {
	const content = "the quick brown fox"
	f := newFixture(t, map[string]string{"a.txt": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.get(t, id, tok, nil)
	if got := sha256hex(string(res.body)); got != f.records[id].SHA256 {
		t.Errorf("delivered sha256 = %s, want indexed %s", got, f.records[id].SHA256)
	}
}
