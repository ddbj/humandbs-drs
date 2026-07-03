package drs

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ddbj/humandbs-drs/internal/index"
	"github.com/ddbj/humandbs-drs/internal/storage"
	"github.com/ddbj/humandbs-drs/internal/token"
)

// serveData streams the object bytes to a client holding a valid session token
// (architecture.md § "配信設計"). It validates the token on every request so a
// revoked grant stops the next request, resolves any Range against the plaintext
// the encryption provider exposes, and honors conditional requests. GET and HEAD
// share this handler; HEAD sends headers only.
func (h *handler) serveData(w http.ResponseWriter, r *http.Request) {
	objectID := r.PathValue("object_id")

	tok, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "session token required")

		return
	}
	sess, err := h.tokens.Validate(tok, objectID)
	switch {
	case errors.Is(err, token.ErrWrongObject):
		writeError(w, http.StatusForbidden, "session token is not valid for this object")

		return
	case err != nil: // unknown or expired: re-authorization required
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "invalid session token")

		return
	}

	rec, ok := h.lookupData(r.Context(), w, objectID)
	if !ok {
		return
	}

	rsc, err := h.backend.Open(r.Context(), rec.Location)
	if err != nil {
		h.logger.Error("open object bytes", "object", rec.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}
	defer func() { _ = rsc.Close() }()

	plain, size, err := h.enc.Reader(rsc, rec.Size)
	if err != nil {
		h.logger.Error("decrypt object", "object", rec.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}

	etag := `"sha256:` + rec.SHA256 + `"`
	modTime := rec.CreatedAt
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", etag)
	if !modTime.IsZero() {
		w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
	}

	if notModified(r, etag, modTime) {
		h.auditDelivery(r, rec, sess, "", 0, http.StatusNotModified)
		w.WriteHeader(http.StatusNotModified)

		return
	}

	status := http.StatusOK
	offset, length := int64(0), size
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" && ifRangeMatches(r, etag, modTime) {
		res, o, l := resolveRange(rangeHeader, size)
		switch res {
		case rangePartial:
			status = http.StatusPartialContent
			offset, length = o, l
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+length-1, size))
		case rangeUnsatisfiable:
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
			h.auditDelivery(r, rec, sess, rangeHeader, 0, http.StatusRequestedRangeNotSatisfiable)
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

			return
		case rangeFull:
			// A multi-range or unparsable Range is ignored: serve the whole object.
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.WriteHeader(status)

	if r.Method == http.MethodHead {
		h.auditDelivery(r, rec, sess, rangeHeader, 0, status)

		return
	}

	n, err := storage.ReadRange(w, plain, size, offset, length)
	if err != nil {
		// Status and headers are already sent; the stream can only be truncated.
		h.logger.Warn("delivery stream truncated", "object", rec.ID, "written", n, "error", err)
	}
	h.auditDelivery(r, rec, sess, rangeHeader, n, status)
}

// lookupData resolves objectID for delivery, writing the 404 or 500 itself. ok
// is false when a response was written. It mirrors lookup but reads the delivery
// path value rather than the DRS {id}.
func (h *handler) lookupData(ctx context.Context, w http.ResponseWriter, objectID string) (index.Record, bool) {
	rec, err := h.idx.Get(ctx, objectID)
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

// serveRevoke revokes a subject's delivery sessions (architecture.md § "配信設
// 計"). It is an internal control-plane endpoint: callers authenticate with the
// configured admin secret, and an unset secret disables revocation (503,
// fail-closed). The body is {"subject", "dataset"}; an empty dataset revokes all
// of the subject's sessions.
func (h *handler) serveRevoke(w http.ResponseWriter, r *http.Request) {
	if h.settings.AdminToken == "" {
		writeError(w, http.StatusServiceUnavailable, "revocation is not configured")

		return
	}
	tok, ok := bearerToken(r)
	if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(h.settings.AdminToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "admin authentication required")

		return
	}

	var body revokeBody
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")

		return
	}
	if body.Subject == "" {
		writeError(w, http.StatusBadRequest, "subject is required")

		return
	}

	n := h.tokens.Revoke(body.Subject, body.Dataset)
	h.logger.Info("sessions revoked", "subject", body.Subject, "dataset", body.Dataset, "revoked", n)
	writeJSON(w, http.StatusOK, revokeResponse{Revoked: n})
}

// auditDelivery records one delivery request for the byte-level audit trail
// (requirements.md § 5.1): who read which object of which dataset, the requested
// range, how many bytes were sent, and the outcome.
func (h *handler) auditDelivery(r *http.Request, rec index.Record, sess token.Session, rangeHeader string, bytesSent int64, status int) {
	h.logger.Info("delivery",
		"method", r.Method,
		"object", rec.ID,
		"dataset", sess.Dataset,
		"subject", sess.Subject,
		"issuer", sess.Issuer,
		"range", rangeHeader,
		"bytes", bytesSent,
		"status", status)
}

// rangeResult is the outcome of resolving a Range header against an object size.
type rangeResult int

const (
	// rangeFull serves the whole object (200): no Range, or one this server does
	// not honor (multiple ranges, or an unparsable header).
	rangeFull rangeResult = iota
	// rangePartial serves [offset, offset+length) as 206.
	rangePartial
	// rangeUnsatisfiable is a syntactically valid range fully outside the object
	// (416).
	rangeUnsatisfiable
)

// resolveRange resolves a single HTTP byte-range against an object of size
// bytes. It supports one range in the forms bytes=start-end, bytes=start-, and
// bytes=-suffix. A syntactically valid range that falls outside the object is
// rangeUnsatisfiable; anything else this server does not serve as partial —
// multiple ranges, a non-"bytes" unit, or a malformed spec — is rangeFull, which
// RFC 7233 permits a server to answer with the whole representation.
func resolveRange(header string, size int64) (rangeResult, int64, int64) {
	const prefix = "bytes="
	if !strings.HasPrefix(header, prefix) {
		return rangeFull, 0, 0
	}
	spec := strings.TrimSpace(header[len(prefix):])
	if spec == "" || strings.Contains(spec, ",") {
		return rangeFull, 0, 0
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return rangeFull, 0, 0
	}
	startStr := strings.TrimSpace(spec[:dash])
	endStr := strings.TrimSpace(spec[dash+1:])

	if startStr == "" {
		// bytes=-suffix: the last suffix bytes.
		if endStr == "" {
			return rangeFull, 0, 0
		}
		suffix, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || suffix < 0 {
			return rangeFull, 0, 0
		}
		if suffix == 0 || size == 0 {
			return rangeUnsatisfiable, 0, 0
		}
		if suffix > size {
			suffix = size
		}

		return rangePartial, size - suffix, suffix
	}

	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 {
		return rangeFull, 0, 0
	}
	if start >= size {
		return rangeUnsatisfiable, 0, 0
	}

	if endStr == "" {
		// bytes=start-: from start to the end.
		return rangePartial, start, size - start
	}
	end, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil || end < start {
		return rangeFull, 0, 0
	}
	if end >= size {
		end = size - 1
	}

	return rangePartial, start, end - start + 1
}

// notModified reports whether a conditional GET should answer 304. If-None-Match
// takes precedence over If-Modified-Since (RFC 7232 § 6). The write-oriented
// If-Match / If-Unmodified-Since are not evaluated on this read-only endpoint.
func notModified(r *http.Request, etag string, modTime time.Time) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		return etagInList(inm, etag)
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil && !modTime.Truncate(time.Second).After(t) {
			return true
		}
	}

	return false
}

// etagInList reports whether the object's etag satisfies an If-None-Match header
// value: "*", or a comma list containing it. Comparison is weak (the W/ prefix
// is ignored), as RFC 7232 § 3.2 specifies for If-None-Match.
func etagInList(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "*" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "W/")
		if part == etag {
			return true
		}
	}

	return false
}

// ifRangeMatches reports whether a Range should be honored given If-Range. With
// no If-Range the range applies. An entity-tag must strong-match the object etag
// (a weak tag never matches); an HTTP-date must equal Last-Modified to the second
// (RFC 7233 § 3.2). A mismatch means the client holds a stale validator, so the
// caller serves the whole current object instead of a range.
func ifRangeMatches(r *http.Request, etag string, modTime time.Time) bool {
	ir := strings.TrimSpace(r.Header.Get("If-Range"))
	if ir == "" {
		return true
	}
	if strings.HasPrefix(ir, "W/") {
		return false
	}
	if strings.HasPrefix(ir, `"`) {
		return ir == etag
	}
	if modTime.IsZero() {
		return false
	}
	t, err := http.ParseTime(ir)
	if err != nil {
		return false
	}

	return t.Unix() == modTime.Unix()
}

// bearerToken extracts the token of an RFC 6750 Authorization header, matching
// the scheme case-insensitively (RFC 7235).
func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}

	return auth[len(prefix):], true
}

// revokeBody is the POST /admin/revoke request body. An empty Dataset revokes all
// of Subject's sessions.
type revokeBody struct {
	Subject string `json:"subject"`
	Dataset string `json:"dataset"`
}

// revokeResponse reports how many sessions the revoke removed.
type revokeResponse struct {
	Revoked int `json:"revoked"`
}
