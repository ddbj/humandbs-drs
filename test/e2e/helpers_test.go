//go:build e2e

// Package e2e drives the controlled-access flow end to end against the
// compose stack (compose.yaml combined with test/e2e/compose.e2e.yaml):
// Keycloak login, passport from the issuer, DRS object and access endpoints,
// authorized byte delivery, and admin revocation, on both storage modes.
// The tests skip unless HUMANDBS_E2E is set so the default `go test ./...`
// stays green without a live stack. Run with:
//
//	make e2e-up
//	make test-e2e
package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fixture identities. These mirror the values wired into the e2e compose
// override and its fixture files; each comment names the file that must agree.
const (
	datasetA = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001" // fixture/drs-manifest.json, fixture/issuer-seed.json, s3-seed command
	datasetB = "https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000002" // fixture/drs-manifest.json (no grant seeded)

	realm    = "humandbs"                             // fixture/realm.json
	clientID = "e2e-cli"                              // fixture/realm.json
	username = "researcher"                           // fixture/realm.json
	password = "researcher-pw"                        // fixture/realm.json
	subject  = "11111111-1111-1111-1111-111111111111" // fixture/realm.json user id == fixture/issuer-seed.json subject

	s3ObjectID = "d9c1b0a8-97e6-45d4-83c2-b1a09f8e7d6c" // -id in the s3-seed command of compose.e2e.yaml
	adminToken = "e2e-admin-secret"                     // HUMANDBS_DRS_ADMIN_TOKEN in compose.e2e.yaml

	issuerInternalURL = "http://issuer:28001" // trusted issuer URL as drs advertises it
)

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return def
}

func drsFSURL() string {
	return getenvDefault("HUMANDBS_E2E_DRS_FS_URL", "http://localhost:28000")
}

func drsS3URL() string {
	return getenvDefault("HUMANDBS_E2E_DRS_S3_URL", "http://localhost:28002")
}

func issuerURL() string {
	return getenvDefault("HUMANDBS_E2E_ISSUER_URL", "http://localhost:28001")
}

func keycloakURL() string {
	return getenvDefault("HUMANDBS_E2E_KEYCLOAK_URL", "http://localhost:8180")
}

var (
	stackOnce sync.Once
	stackErr  error
)

// requireStack gates each test on HUMANDBS_E2E and, once per run, waits for
// every service to answer before the first scenario fires: the drs containers
// restart until the issuer's JWKS is reachable, so readiness is when they stay
// up, not when compose returns.
func requireStack(t *testing.T) {
	t.Helper()
	if os.Getenv("HUMANDBS_E2E") == "" {
		t.Skip("HUMANDBS_E2E is not set; skipping end-to-end test (make e2e-up, then make test-e2e)")
	}
	stackOnce.Do(func() { stackErr = waitForStack() })
	if stackErr != nil {
		t.Fatal(stackErr)
	}
}

// waitForStack polls until every service is ready. Keycloak has no /healthz;
// its OIDC discovery document doubles as readiness and proves the realm import
// finished.
func waitForStack() error {
	ready := map[string]string{
		"drs (fs)": drsFSURL() + "/healthz",
		"drs (s3)": drsS3URL() + "/healthz",
		"issuer":   issuerURL() + "/healthz",
		"keycloak": keycloakURL() + "/realms/" + realm + "/.well-known/openid-configuration",
	}
	deadline := time.Now().Add(120 * time.Second)
	for name, probe := range ready {
		for {
			resp, err := http.Get(probe)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("e2e stack: %s did not become ready at %s (last error: %v)", name, probe, err)
			}
			time.Sleep(time.Second)
		}
	}

	return nil
}

// The response shapes are declared here rather than imported from
// internal/drs, so the tests pin the wire format a real client sees.
type drsObject struct {
	ID          string `json:"id"`
	SelfURI     string `json:"self_uri"`
	Size        int64  `json:"size"`
	CreatedTime string `json:"created_time"`
	Checksums   []struct {
		Checksum string `json:"checksum"`
		Type     string `json:"type"`
	} `json:"checksums"`
	AccessMethods []struct {
		Type     string `json:"type"`
		AccessID string `json:"access_id"`
	} `json:"access_methods"`
}

type authorizations struct {
	SupportedTypes      []string `json:"supported_types"`
	PassportAuthIssuers []string `json:"passport_auth_issuers"`
}

type accessURL struct {
	URL     string   `json:"url"`
	Headers []string `json:"headers"`
}

// doJSON sends req, requires wantStatus, and decodes the body into out when
// out is non-nil.
func doJSON(t *testing.T, req *http.Request, wantStatus int, out any) http.Header {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read body: %v", req.Method, req.URL, err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: status %d, want %d (body: %s)", req.Method, req.URL, resp.StatusCode, wantStatus, body)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			t.Fatalf("%s %s: decode body %q: %v", req.Method, req.URL, body, err)
		}
	}

	return resp.Header
}

// passwordGrant logs the fixture user in via the direct grant flow and
// returns the Keycloak access token.
func passwordGrant(t *testing.T) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
	}
	resp, err := http.PostForm(keycloakURL()+"/realms/"+realm+"/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatalf("password grant: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("password grant: read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password grant: status %d (body: %s)", resp.StatusCode, body)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil || token.AccessToken == "" {
		t.Fatalf("password grant: no access_token in %q (%v)", body, err)
	}

	return token.AccessToken
}

// jwtSubject reads the sub claim out of a JWT without verifying it; signature
// verification is the issuer's and the clearinghouse's job, the test only
// needs the subject to address /permissions/{user}.
func jwtSubject(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT (%d segments)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse JWT payload %q: %v", payload, err)
	}
	if claims.Sub == "" {
		t.Fatal("access token has no sub claim")
	}

	return claims.Sub
}

// fetchPassport exchanges a Keycloak access token for the signed passport of
// its subject.
func fetchPassport(t *testing.T, sub, accessToken string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, issuerURL()+"/permissions/"+sub, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	var body struct {
		Passport string `json:"passport"`
	}
	doJSON(t, req, http.StatusOK, &body)
	if body.Passport == "" {
		t.Fatal("issuer returned an empty passport")
	}

	return body.Passport
}

// grantedPassport runs the full login: password grant, subject extraction,
// and passport fetch for the fixture user.
func grantedPassport(t *testing.T) string {
	t.Helper()
	token := passwordGrant(t)
	sub := jwtSubject(t, token)
	if sub != subject {
		t.Fatalf("access token sub = %q, want fixture subject %q", sub, subject)
	}

	return fetchPassport(t, sub, token)
}

func objectPath(drsURL, id string) string {
	return drsURL + "/ga4gh/drs/v1/objects/" + id
}

// postAccess presents passports to the access endpoint and returns the
// response status with the decoded AccessURL (zero unless authorized).
func postAccess(t *testing.T, drsURL, id string, passports []string) (int, accessURL, http.Header) {
	t.Helper()
	body, err := json.Marshal(map[string][]string{"passports": passports})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, objectPath(drsURL, id)+"/access/0", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST access: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("POST access: read body: %v", err)
	}
	var access accessURL
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(respBody, &access); err != nil {
			t.Fatalf("POST access: decode %q: %v", respBody, err)
		}
	}

	return resp.StatusCode, access, resp.Header
}

// download fetches the bytes behind an AccessURL. The URL scheme is https
// because TLS termination belongs to the upstream gateway (architecture.md
// § 1); the compose stack has no gateway, so the test reaches the drs process
// directly over http.
func download(t *testing.T, access accessURL, rangeHeader string) (int, []byte, http.Header) {
	t.Helper()
	plainURL := strings.Replace(access.URL, "https://", "http://", 1)
	req, err := http.NewRequest(http.MethodGet, plainURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range access.Headers {
		name, value, ok := strings.Cut(h, ": ")
		if !ok {
			t.Fatalf("access header %q is not %q separated", h, ": ")
		}
		req.Header.Set(name, value)
	}
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", plainURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", plainURL, err)
	}

	return resp.StatusCode, body, resp.Header
}

// adminRevoke calls the internal revocation endpoint and returns the response
// status and the number of sessions revoked.
func adminRevoke(t *testing.T, drsURL, revokeSubject, dataset string) (int, int) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"subject": revokeSubject, "dataset": dataset})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, drsURL+"/admin/revoke", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /admin/revoke: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("POST /admin/revoke: read body: %v", err)
	}
	var out struct {
		Revoked int `json:"revoked"`
	}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(respBody, &out); err != nil {
			t.Fatalf("POST /admin/revoke: decode %q: %v", respBody, err)
		}
	}

	return resp.StatusCode, out.Revoked
}

// fixturePayload reads a payload file from the fixture tree, the same bytes
// the compose override mounts into the storage backends.
func fixturePayload(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read fixture payload: %v", err)
	}

	return data
}
