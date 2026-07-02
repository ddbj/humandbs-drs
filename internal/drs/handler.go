package drs

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ddbj/humandbs-drs/internal/index"
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
)

// Settings holds the deployment-supplied values the handler needs to build
// self URIs, service-info, and the OPTIONS authorizations.
type Settings struct {
	PublicHost     string
	ServiceID      string
	ServiceName    string
	OrgName        string
	OrgURL         string
	Version        string
	TrustedIssuers []string
}

// handler serves the DRS API over the derived index.
type handler struct {
	idx      *index.Index
	settings Settings
	logger   *slog.Logger
}

// NewHandler wires the DRS 1.5 endpoints (architecture.md § "DRS server 設計"):
//
//   - GET /service-info — service metadata
//   - GET/POST /objects/{id} — the Object (POST also accepts passports)
//   - OPTIONS /objects/{id} — the supported authorizations
//   - GET/POST /objects/{id}/access/{access_id} — the AccessURL once authorized
//
// The mux registers full paths including BasePath, so the returned handler is
// self-contained and can be mounted at "/".
func NewHandler(idx *index.Index, s Settings, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{idx: idx, settings: s, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+BasePath+"/service-info", h.serveServiceInfo)
	mux.HandleFunc("GET "+BasePath+"/objects/{id}", h.serveObject)
	mux.HandleFunc("POST "+BasePath+"/objects/{id}", h.serveObject)
	mux.HandleFunc("OPTIONS "+BasePath+"/objects/{id}", h.serveOptions)
	mux.HandleFunc("GET "+BasePath+"/objects/{id}/access/{access_id}", h.serveAccess)
	mux.HandleFunc("POST "+BasePath+"/objects/{id}/access/{access_id}", h.serveAccess)

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
// body's expand and passports are accepted but not yet acted on; authorization
// is applied by the Clearinghouse in a later stage.
func (h *handler) serveObject(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body postObjectBody
		if err := decodeJSON(r, &body); err != nil {
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

// serveAccess answers GET and POST /objects/{id}/access/{access_id}. An unknown
// object or access_id is 404; a known one requires passport authorization,
// which is not yet implemented, so the response is 401.
func (h *handler) serveAccess(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.lookup(w, r); !ok {
		return
	}
	if r.PathValue("access_id") != accessID {
		writeError(w, http.StatusNotFound, "access not found")

		return
	}
	if r.Method == http.MethodPost {
		var body passportsBody
		if err := decodeJSON(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")

			return
		}
	}

	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "passport authorization required")
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

// decodeJSON reads a JSON request body into dst. An empty body is allowed; a
// malformed one is an error.
func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
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
