// Package drs serves the DRS 1.5.0 API (base path /ga4gh/drs/v1) over the
// derived index, returning Objects assembled from storage. Authorization is
// handled by the Clearinghouse in a later stage; access endpoints require a
// passport and answer 401 until then (architecture.md § "DRS server 設計").
package drs

// Object is the metadata for a single blob (a data-repository-service-schemas
// 1.5.0 DrsObject). Bundles (contents) are not served.
type Object struct {
	ID            string         `json:"id"`
	SelfURI       string         `json:"self_uri"`
	Size          int64          `json:"size"`
	CreatedTime   string         `json:"created_time"`
	Checksums     []Checksum     `json:"checksums"`
	AccessMethods []AccessMethod `json:"access_methods"`
}

// Checksum is one digest of the object bytes. Type is an IANA Named Information
// Hash Algorithm name; this server emits sha-256.
type Checksum struct {
	Checksum string `json:"checksum"`
	Type     string `json:"type"`
}

// AccessMethod tells a client how to fetch the bytes. The URL is not embedded;
// AccessID names the entry the client resolves through the access endpoint so
// the delivery URL is not exposed before authorization.
type AccessMethod struct {
	Type     string `json:"type"`
	AccessID string `json:"access_id"`
}

// AccessURL is a resolvable location for the object bytes with any headers a
// client must send. Returned by the access endpoint once authorized.
type AccessURL struct {
	URL     string   `json:"url"`
	Headers []string `json:"headers,omitempty"`
}

// Authorizations advertises how an object may be authorized, returned by
// OPTIONS /objects/{id}. This server offers PassportAuth over TrustedIssuers.
type Authorizations struct {
	DrsObjectID         string   `json:"drs_object_id"`
	SupportedTypes      []string `json:"supported_types"`
	PassportAuthIssuers []string `json:"passport_auth_issuers"`
}

// ServiceInfo is the GA4GH service-info response with the DRS extension. Both
// the deprecated top-level MaxBulkRequestLength and DRS.MaxBulkRequestLength are
// emitted for schema compliance even though bulk endpoints are not served.
type ServiceInfo struct {
	ID                   string       `json:"id"`
	Name                 string       `json:"name"`
	Type                 ServiceType  `json:"type"`
	Organization         Organization `json:"organization"`
	Version              string       `json:"version"`
	MaxBulkRequestLength int          `json:"maxBulkRequestLength"`
	DRS                  Service      `json:"drs"`
}

// ServiceType identifies the service in the GA4GH service-info type registry.
type ServiceType struct {
	Group    string `json:"group"`
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
}

// Organization names the group running the service.
type Organization struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Service is the DRS-specific section of service-info.
type Service struct {
	MaxBulkRequestLength int `json:"maxBulkRequestLength"`
}

// Error is the DRS error body (msg, status_code).
type Error struct {
	Msg        string `json:"msg"`
	StatusCode int    `json:"status_code"`
}
