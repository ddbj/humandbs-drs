//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ddbj/humandbs-drs/internal/storage"
)

// mode binds one drs instance to the fixture object it serves. publicHost is
// the -public-host the instance runs with, so it must appear verbatim in
// self_uri and the AccessURL.
type mode struct {
	name        string
	drsURL      string
	publicHost  string
	objectID    string
	payloadPath string
}

func modes() []mode {
	return []mode{
		{
			name:        "fs",
			drsURL:      drsFSURL(),
			publicHost:  "localhost:28000",
			objectID:    storage.ObjectID(datasetA, "payload.bin"),
			payloadPath: "fixture/testdata/fs/jgad000001/payload.bin",
		},
		{
			name:        "s3",
			drsURL:      drsS3URL(),
			publicHost:  "localhost:28002",
			objectID:    s3ObjectID,
			payloadPath: "fixture/testdata/s3/payload.bin",
		},
	}
}

// TestControlledAccessHappyPath walks the whole controlled-access flow
// (architecture.md § "controlled access フロー") on both storage modes:
// login, passport, OPTIONS advertisement, object metadata, access
// authorization, and byte delivery with a range read.
func TestControlledAccessHappyPath(t *testing.T) {
	requireStack(t)
	for _, m := range modes() {
		t.Run(m.name, func(t *testing.T) {
			payload := fixturePayload(t, m.payloadPath)
			passport := grantedPassport(t)

			// OPTIONS advertises PassportAuth over the pinned issuer.
			req, err := http.NewRequest(http.MethodOptions, objectPath(m.drsURL, m.objectID), nil)
			if err != nil {
				t.Fatal(err)
			}
			var auth authorizations
			doJSON(t, req, http.StatusOK, &auth)
			if len(auth.SupportedTypes) != 1 || auth.SupportedTypes[0] != "PassportAuth" {
				t.Fatalf("supported_types = %v, want [PassportAuth]", auth.SupportedTypes)
			}
			if len(auth.PassportAuthIssuers) != 1 || auth.PassportAuthIssuers[0] != issuerInternalURL {
				t.Fatalf("passport_auth_issuers = %v, want [%s]", auth.PassportAuthIssuers, issuerInternalURL)
			}

			// The object metadata is public tier and must describe the plaintext.
			req, err = http.NewRequest(http.MethodGet, objectPath(m.drsURL, m.objectID), nil)
			if err != nil {
				t.Fatal(err)
			}
			var obj drsObject
			doJSON(t, req, http.StatusOK, &obj)
			if obj.ID != m.objectID {
				t.Fatalf("object id = %q, want %q", obj.ID, m.objectID)
			}
			if want := "drs://" + m.publicHost + "/" + m.objectID; obj.SelfURI != want {
				t.Fatalf("self_uri = %q, want %q", obj.SelfURI, want)
			}
			if obj.Size != int64(len(payload)) {
				t.Fatalf("size = %d, want %d", obj.Size, len(payload))
			}
			if obj.CreatedTime == "" {
				t.Fatal("created_time is empty")
			}
			wantSum := sha256.Sum256(payload)
			if len(obj.Checksums) != 1 || obj.Checksums[0].Type != "sha-256" || obj.Checksums[0].Checksum != hex.EncodeToString(wantSum[:]) {
				t.Fatalf("checksums = %+v, want one sha-256 of the fixture payload", obj.Checksums)
			}
			if len(obj.AccessMethods) != 1 || obj.AccessMethods[0].Type != "https" || obj.AccessMethods[0].AccessID != "0" {
				t.Fatalf("access_methods = %+v, want [{https 0}]", obj.AccessMethods)
			}

			// A valid passport authorizes access and yields the delivery URL.
			status, access, _ := postAccess(t, m.drsURL, m.objectID, []string{passport})
			if status != http.StatusOK {
				t.Fatalf("POST access status = %d, want 200", status)
			}
			if want := "https://" + m.publicHost + "/data/" + m.objectID; access.URL != want {
				t.Fatalf("access url = %q, want %q", access.URL, want)
			}
			if len(access.Headers) != 1 || !strings.HasPrefix(access.Headers[0], "Authorization: Bearer ") {
				t.Fatalf("access headers = %v, want one bearer Authorization", access.Headers)
			}

			// Delivery streams the exact fixture bytes.
			status, body, hdr := download(t, access, "")
			if status != http.StatusOK {
				t.Fatalf("download status = %d, want 200", status)
			}
			if !bytes.Equal(body, payload) {
				t.Fatalf("downloaded %d bytes differing from the fixture payload", len(body))
			}
			if hdr.Get("Accept-Ranges") != "bytes" {
				t.Fatalf("Accept-Ranges = %q, want bytes", hdr.Get("Accept-Ranges"))
			}

			// A range read re-validates the token and serves the slice.
			status, part, hdr := download(t, access, "bytes=0-3")
			if status != http.StatusPartialContent {
				t.Fatalf("range download status = %d, want 206", status)
			}
			if want := fmt.Sprintf("bytes 0-3/%d", len(payload)); hdr.Get("Content-Range") != want {
				t.Fatalf("Content-Range = %q, want %q", hdr.Get("Content-Range"), want)
			}
			if !bytes.Equal(part, payload[:4]) {
				t.Fatalf("range body = %q, want %q", part, payload[:4])
			}
		})
	}
}

// TestRevokeStopsDelivery pins the revocation guarantee (requirements § 4.7):
// after an admin revoke of the (subject, dataset) pair, the very next request
// with the already-issued session token is refused.
func TestRevokeStopsDelivery(t *testing.T) {
	requireStack(t)
	for _, m := range modes() {
		t.Run(m.name, func(t *testing.T) {
			passport := grantedPassport(t)
			status, access, _ := postAccess(t, m.drsURL, m.objectID, []string{passport})
			if status != http.StatusOK {
				t.Fatalf("POST access status = %d, want 200", status)
			}
			if status, _, _ := download(t, access, ""); status != http.StatusOK {
				t.Fatalf("download before revoke status = %d, want 200", status)
			}

			status, revoked := adminRevoke(t, m.drsURL, subject, datasetA)
			if status != http.StatusOK {
				t.Fatalf("revoke status = %d, want 200", status)
			}
			if revoked < 1 {
				t.Fatalf("revoked = %d, want at least 1", revoked)
			}

			status, _, hdr := download(t, access, "")
			if status != http.StatusUnauthorized {
				t.Fatalf("download after revoke status = %d, want 401", status)
			}
			if hdr.Get("WWW-Authenticate") == "" {
				t.Fatal("download after revoke has no WWW-Authenticate header")
			}

			// The grant itself is untouched, so re-authorization succeeds: only
			// the sessions died, which is exactly the revocation unit.
			if status, _, _ := postAccess(t, m.drsURL, m.objectID, []string{passport}); status != http.StatusOK {
				t.Fatalf("re-authorization after revoke status = %d, want 200", status)
			}
		})
	}
}

// TestAccessRequiresPassport pins the unauthenticated path: no passport means
// 401 with a bearer challenge, and the delivery endpoint refuses a bare
// request the same way.
func TestAccessRequiresPassport(t *testing.T) {
	requireStack(t)
	m := modes()[0] // one mode suffices: the clearinghouse path is shared code

	status, _, hdr := postAccess(t, m.drsURL, m.objectID, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("POST access without passport status = %d, want 401", status)
	}
	if !strings.HasPrefix(hdr.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("WWW-Authenticate = %q, want a Bearer challenge", hdr.Get("WWW-Authenticate"))
	}

	access := accessURL{URL: "https://" + m.publicHost + "/data/" + m.objectID}
	if status, _, _ := download(t, access, ""); status != http.StatusUnauthorized {
		t.Fatalf("download without token status = %d, want 401", status)
	}
}

// TestAccessDeniedForUngrantedDataset presents a passport that is valid but
// asserts a different dataset: the clearinghouse must answer 403, not 401
// (architecture.md § "認可判断").
func TestAccessDeniedForUngrantedDataset(t *testing.T) {
	requireStack(t)
	m := modes()[0]
	passport := grantedPassport(t) // grants datasetA only
	ungranted := storage.ObjectID(datasetB, "payload.bin")

	status, _, _ := postAccess(t, m.drsURL, ungranted, []string{passport})
	if status != http.StatusForbidden {
		t.Fatalf("POST access for ungranted dataset status = %d, want 403", status)
	}
}
