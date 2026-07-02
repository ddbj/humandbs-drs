package issuer

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// passportResponse is the body of GET /permissions/{user}: the user's visas
// under the ga4gh_passport_v1 claim name (requirements.md § 4.4). Passport is
// never nil so a user without grants receives an empty array, not null.
type passportResponse struct {
	Passport []string `json:"ga4gh_passport_v1"`
}

// handler serves the issuer HTTP API.
type handler struct {
	verifier *OIDCVerifier
	store    *GrantStore
	passport *PassportIssuer
	jwks     []byte
	logger   *slog.Logger
}

// NewHandler wires the issuer endpoints (architecture.md § "Issuer 設計"):
//
//   - GET /jwks — the visa-verification public keys, as jwksJSON
//   - GET /permissions/{user} — the user's Passport, minted from their active
//     grants after their access token is verified
func NewHandler(verifier *OIDCVerifier, store *GrantStore, passport *PassportIssuer, jwksJSON []byte, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{verifier: verifier, store: store, passport: passport, jwks: jwksJSON, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", h.serveJWKS)
	mux.HandleFunc("GET /permissions/{user}", h.servePermissions)

	return mux
}

func (h *handler) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.jwks)
}

// servePermissions authenticates the caller, requires the authenticated subject
// to be the {user} being asked about, and responds with the Passport minted
// from the subject's active grants.
func (h *handler) servePermissions(w http.ResponseWriter, r *http.Request) {
	raw, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "missing bearer token")

		return
	}
	subject, err := h.verifier.Verify(r.Context(), raw)
	if err != nil {
		h.logger.Info("access token rejected", "error", err)
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		writeError(w, http.StatusUnauthorized, "invalid access token")

		return
	}
	if user := r.PathValue("user"); subject != user {
		writeError(w, http.StatusForbidden, "token subject does not match requested user")

		return
	}

	grants, err := h.store.ActiveBySubject(r.Context(), subject)
	if err != nil {
		h.logger.Error("list active grants", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}
	visas, err := h.passport.Passport(subject, grants)
	if err != nil {
		h.logger.Error("mint passport", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}

	writeJSON(w, http.StatusOK, passportResponse{Passport: visas})
}

// bearerToken extracts the token of an RFC 6750 Authorization header. The
// scheme is matched case-insensitively per RFC 7235.
func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}

	return auth[len(prefix):], true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
