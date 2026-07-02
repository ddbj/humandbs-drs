package drs_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ddbj/humandbs-drs/internal/drs"
)

func TestServiceInfo(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})

	resp, err := http.Get(f.url("/service-info"))
	if err != nil {
		t.Fatalf("GET service-info: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var info drs.ServiceInfo
	decodeBody(t, resp, &info)
	if info.Type.Group != "org.ga4gh" || info.Type.Artifact != "drs" || info.Type.Version != "1.5" {
		t.Errorf("type = %+v, want group=org.ga4gh artifact=drs version=1.5", info.Type)
	}
	if info.ID != "jp.ac.nig.ddbj.humandbs-drs" {
		t.Errorf("id = %q, want %q", info.ID, "jp.ac.nig.ddbj.humandbs-drs")
	}
	if info.Name != "HumanDBs DRS" {
		t.Errorf("name = %q, want %q", info.Name, "HumanDBs DRS")
	}
	if info.Organization.Name != "DDBJ" || info.Organization.URL != "https://www.ddbj.nig.ac.jp/" {
		t.Errorf("organization = %+v", info.Organization)
	}
	if info.MaxBulkRequestLength < 1 || info.DRS.MaxBulkRequestLength < 1 {
		t.Errorf("maxBulkRequestLength = %d / drs %d, want >= 1", info.MaxBulkRequestLength, info.DRS.MaxBulkRequestLength)
	}
}

func TestGetObject(t *testing.T) {
	const content = "hello world"
	f := newFixture(t, map[string]string{"data.txt": content})
	id := f.ids[0]
	rec := f.records[id]

	resp, err := http.Get(f.url("/objects/" + id))
	if err != nil {
		t.Fatalf("GET object: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var obj drs.Object
	decodeBody(t, resp, &obj)
	if obj.ID != id {
		t.Errorf("id = %q, want %q", obj.ID, id)
	}
	if want := "drs://drs.example.org/" + id; obj.SelfURI != want {
		t.Errorf("self_uri = %q, want %q", obj.SelfURI, want)
	}
	if obj.Size != rec.Size || obj.Size != int64(len(content)) {
		t.Errorf("size = %d, want %d", obj.Size, len(content))
	}
	if len(obj.Checksums) != 1 || obj.Checksums[0].Type != "sha-256" {
		t.Fatalf("checksums = %+v, want one sha-256", obj.Checksums)
	}
	if obj.Checksums[0].Checksum != sha256hex(content) || obj.Checksums[0].Checksum != rec.SHA256 {
		t.Errorf("checksum = %q, want %q", obj.Checksums[0].Checksum, sha256hex(content))
	}
	if _, err := time.Parse(time.RFC3339, obj.CreatedTime); err != nil {
		t.Errorf("created_time %q is not RFC3339: %v", obj.CreatedTime, err)
	}
	if len(obj.AccessMethods) != 1 {
		t.Fatalf("access_methods = %+v, want one method", obj.AccessMethods)
	}
	if m := obj.AccessMethods[0]; m.Type != "https" || m.AccessID != "0" {
		t.Errorf("access_method = %+v, want {https 0}", m)
	}
}

func TestPostObjectAcceptsPassports(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})
	id := f.ids[0]

	body := strings.NewReader(`{"expand":true,"passports":["header.payload.sig"]}`)
	resp, err := http.Post(f.url("/objects/"+id), "application/json", body)
	if err != nil {
		t.Fatalf("POST object: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var obj drs.Object
	decodeBody(t, resp, &obj)
	if obj.ID != id {
		t.Errorf("id = %q, want %q", obj.ID, id)
	}
}

func TestPostObjectRejectsMalformedBody(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})
	id := f.ids[0]

	resp, err := http.Post(f.url("/objects/"+id), "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatalf("POST object: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestExpandQueryIgnoredForBlob(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})
	id := f.ids[0]

	for _, q := range []string{"?expand=true", "?expand=false", ""} {
		resp, err := http.Get(f.url("/objects/" + id + q))
		if err != nil {
			t.Fatalf("GET %q: %v", q, err)
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status != http.StatusOK {
			t.Errorf("expand %q: status = %d, want 200", q, status)
		}
	}
}

func TestUnknownObjectReturns404(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, err := http.NewRequest(method, f.url("/objects/nonexistent"), nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if resp.StatusCode != http.StatusNotFound {
			_ = resp.Body.Close()
			t.Fatalf("%s: status = %d, want 404", method, resp.StatusCode)
		}
		var e drs.Error
		decodeBody(t, resp, &e)
		_ = resp.Body.Close()
		if e.StatusCode != http.StatusNotFound || e.Msg == "" {
			t.Errorf("%s: error body = %+v, want msg set and status_code 404", method, e)
		}
	}
}

func TestOptionsAdvertisesPassportAuth(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})
	id := f.ids[0]

	req, err := http.NewRequest(http.MethodOptions, f.url("/objects/"+id), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var auth drs.Authorizations
	decodeBody(t, resp, &auth)
	if len(auth.SupportedTypes) != 1 || auth.SupportedTypes[0] != "PassportAuth" {
		t.Errorf("supported_types = %v, want [PassportAuth]", auth.SupportedTypes)
	}
	if len(auth.PassportAuthIssuers) != 1 || auth.PassportAuthIssuers[0] != "https://issuer.example.org" {
		t.Errorf("passport_auth_issuers = %v, want [https://issuer.example.org]", auth.PassportAuthIssuers)
	}
	if auth.DrsObjectID != id {
		t.Errorf("drs_object_id = %q, want %q", auth.DrsObjectID, id)
	}
}

func TestOptionsUnknownObjectReturns404(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})

	req, err := http.NewRequest(http.MethodOptions, f.url("/objects/nope"), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAccessRequiresAuthorization(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})
	id := f.ids[0]

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, err := http.NewRequest(method, f.url("/objects/"+id+"/access/0"), nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		status := resp.StatusCode
		authnHeader := resp.Header.Get("WWW-Authenticate")
		_ = resp.Body.Close()
		if status != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", method, status)
		}
		if authnHeader == "" {
			t.Errorf("%s: missing WWW-Authenticate header", method)
		}
	}
}

func TestAccessUnknownAccessIDReturns404(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})
	id := f.ids[0]

	resp, err := http.Get(f.url("/objects/" + id + "/access/bad"))
	if err != nil {
		t.Fatalf("GET access: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAccessUnknownObjectReturns404(t *testing.T) {
	f := newFixture(t, map[string]string{"a.txt": "aaa"})

	resp, err := http.Get(f.url("/objects/nope/access/0"))
	if err != nil {
		t.Fatalf("GET access: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}
