package drs

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ddbj/humandbs-drs/internal/clearinghouse"
	"github.com/ddbj/humandbs-drs/internal/encryption"
	"github.com/ddbj/humandbs-drs/internal/index"
	"github.com/ddbj/humandbs-drs/internal/storage"
	"github.com/ddbj/humandbs-drs/internal/token"
)

const (
	// BasePath is the DRS 1.5 API prefix (requirements.md § 4.1).
	BasePath = "/ga4gh/drs/v1"

	accessID     = "0"
	checksumType = "sha-256"
	accessType   = "https"

	typeGroup    = "org.ga4gh"
	typeArtifact = "drs"
	typeVersion  = "1.5"

	// maxBulkRequestLength is emitted for service-info schema compliance; bulk
	// endpoints are not served.
	maxBulkRequestLength = 1

	// maxBodyBytes caps request bodies; a passports array has no business being
	// larger (architecture.md § "Clearinghouse 設計").
	maxBodyBytes = 1 << 20
)

// Settings holds the deployment-supplied values the handler needs to build
// self URIs, service-info, the OPTIONS authorizations, and to authenticate the
// admin revoke endpoint.
type Settings struct {
	PublicHost     string
	ServiceID      string
	ServiceName    string
	OrgName        string
	OrgURL         string
	Version        string
	TrustedIssuers []string
	// AdminToken is the shared secret authenticating POST /admin/revoke. Empty
	// disables revocation (the endpoint answers 503), so it is fail-closed
	// (architecture.md § "配信設計").
	AdminToken string
}

// handler serves the DRS API over the derived index, deciding access with the
// Clearinghouse, issuing session tokens, and streaming authorized bytes from
// the storage backend through the encryption provider.
type handler struct {
	idx      *index.Index
	backend  storage.Backend
	ch       *clearinghouse.Clearinghouse
	tokens   *token.Store
	enc      encryption.Provider
	settings Settings
	logger   *slog.Logger
}

// NewHandler wires the DRS 1.5 endpoints (architecture.md § "DRS server 設計")
// plus the authorized delivery and admin revoke endpoints (§ "配信設計"):
//
//   - GET /service-info — service metadata
//   - GET/POST /objects/{id} — the Object (POST also accepts passports)
//   - OPTIONS /objects/{id} — the supported authorizations
//   - GET/POST /objects/{id}/access/{access_id} — the AccessURL once authorized
//   - GET/HEAD /data/{object_id} — the object bytes, per-request session token
//   - POST /admin/revoke — revoke a subject's sessions (internal, admin secret)
//
// The mux registers full paths, so the returned handler is self-contained and
// is mounted at "/" (the delivery and admin paths sit outside BasePath).
func NewHandler(idx *index.Index, backend storage.Backend, ch *clearinghouse.Clearinghouse, tokens *token.Store, enc encryption.Provider, s Settings, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{idx: idx, backend: backend, ch: ch, tokens: tokens, enc: enc, settings: s, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+BasePath+"/service-info", h.serveServiceInfo)
	mux.HandleFunc("GET "+BasePath+"/objects/{id}", h.serveObject)
	mux.HandleFunc("POST "+BasePath+"/objects/{id}", h.serveObject)
	mux.HandleFunc("OPTIONS "+BasePath+"/objects/{id}", h.serveOptions)
	mux.HandleFunc("GET "+BasePath+"/objects/{id}/access/{access_id}", h.serveAccess)
	mux.HandleFunc("POST "+BasePath+"/objects/{id}/access/{access_id}", h.serveAccess)
	// A GET pattern also matches HEAD (net/http ServeMux), so serveData handles
	// both and skips the body for HEAD.
	mux.HandleFunc("GET /data/{object_id}", h.serveData)
	mux.HandleFunc("POST /admin/revoke", h.serveRevoke)

	return mux
}

func (h *handler) serveServiceInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, ServiceInfo{
		ID:                   h.settings.ServiceID,
		Name:                 h.settings.ServiceName,
		Type:                 ServiceType{Group: typeGroup, Artifact: typeArtifact, Version: typeVersion},
		Organization:         Organization{Name: h.settings.OrgName, URL: h.settings.OrgURL},
		Version:              h.settings.Version,
		MaxBulkRequestLength: maxBulkRequestLength,
		DRS:                  Service{MaxBulkRequestLength: maxBulkRequestLength},
	})
}

// serveObject answers GET and POST /objects/{id} with the Object. The POST
// body's passports are accepted but not used for authorization: object
// metadata is public and the Object never embeds an access_url
// (architecture.md § "Clearinghouse 設計"), so nothing in the response depends
// on it. expand is accepted and ignored because bundles are not served.
func (h *handler) serveObject(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body postObjectBody
		if err := decodeJSON(w, r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")

			return
		}
	}

	rec, ok := h.lookup(w, r)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, h.drsObject(rec))
}

// serveOptions advertises the object's supported authorizations.
func (h *handler) serveOptions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.lookup(w, r); !ok {
		return
	}

	writeJSON(w, http.StatusOK, Authorizations{
		DrsObjectID:         r.PathValue("id"),
		SupportedTypes:      []string{"PassportAuth"},
		PassportAuthIssuers: h.settings.TrustedIssuers,
	})
}

// serveAccess answers GET and POST /objects/{id}/access/{access_id}. An
// unknown object or access_id is 404. The POST body's passports go through the
// Clearinghouse: authorization mints a session token and returns the AccessURL
// of the delivery endpoint; a request without a usable credential is 401 and a
// verified one without a grant for this object's dataset is 403
// (architecture.md § "DRS server 設計"). A GET carries no passports and is
// always 401.
func (h *handler) serveAccess(w http.ResponseWriter, r *http.Request) {
	rec, ok := h.lookup(w, r)
	if !ok {
		return
	}
	if r.PathValue("access_id") != accessID {
		writeError(w, http.StatusNotFound, "access not found")

		return
	}

	var body passportsBody
	if r.Method == http.MethodPost {
		if err := decodeJSON(w, r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")

			return
		}
	}

	grant, err := h.ch.Authorize(r.Context(), body.Passports, rec.DatasetURL)
	switch {
	case errors.Is(err, clearinghouse.ErrNoValidPassport):
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "passport authorization required")

		return
	case errors.Is(err, clearinghouse.ErrNotAuthorized):
		writeError(w, http.StatusForbidden, "passport grants no access to this object")

		return
	case err != nil:
		h.logger.Error("authorize access", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}

	tok, _, err := h.tokens.Issue(rec.ID, rec.DatasetURL, grant.Subject, grant.Issuer)
	if err != nil {
		h.logger.Error("issue session token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}
	h.logger.Info("access granted",
		"object", rec.ID, "dataset", rec.DatasetURL,
		"subject", grant.Subject, "issuer", grant.Issuer, "jti", grant.JTI)

	writeJSON(w, http.StatusOK, AccessURL{
		URL:     "https://" + h.settings.PublicHost + "/data/" + rec.ID,
		Headers: []string{"Authorization: Bearer " + tok},
	})
}

// lookup resolves the {id} path value to a Record, writing the 404 or 500
// response itself when it cannot. ok is false when a response was written.
func (h *handler) lookup(w http.ResponseWriter, r *http.Request) (index.Record, bool) {
	rec, err := h.idx.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, index.ErrObjectNotFound) {
			writeError(w, http.StatusNotFound, "object not found")

			return index.Record{}, false
		}
		h.logger.Error("index get", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return index.Record{}, false
	}

	return rec, true
}

func (h *handler) drsObject(rec index.Record) Object {
	return Object{
		ID:            rec.ID,
		SelfURI:       "drs://" + h.settings.PublicHost + "/" + rec.ID,
		Size:          rec.Size,
		CreatedTime:   rec.CreatedAt.UTC().Format(time.RFC3339),
		Checksums:     []Checksum{{Checksum: rec.SHA256, Type: checksumType}},
		AccessMethods: []AccessMethod{{Type: accessType, AccessID: accessID}},
	}
}

// postObjectBody is the POST /objects/{id} request body.
type postObjectBody struct {
	Expand    bool     `json:"expand"`
	Passports []string `json:"passports"`
}

// passportsBody is the POST /objects/{id}/access/{access_id} request body.
type passportsBody struct {
	Passports []string `json:"passports"`
}

// decodeJSON reads a JSON request body into dst, refusing bodies over
// maxBodyBytes. An empty body is allowed; a malformed or oversized one is an
// error.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}

		return err
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, Error{Msg: msg, StatusCode: status})
}
