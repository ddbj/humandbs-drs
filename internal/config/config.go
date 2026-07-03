// Package config resolves process configuration from command-line flags and
// environment variables. Explicit flags take precedence over environment
// variables, which take precedence over built-in defaults. An empty
// environment value is treated as unset.
package config

import (
	"flag"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TrustedIssuer names a visa issuer the DRS Clearinghouse trusts and the JWKS
// URL its verification keys are pinned from at startup
// (architecture.md § "Clearinghouse 設計").
type TrustedIssuer struct {
	// Issuer is the issuer URL, matched verbatim against the token `iss` claim.
	Issuer string
	// JWKSURL is fetched once at startup to pin the issuer's public keys; a
	// token `jku` header must equal it exactly.
	JWKSURL string
}

// DRSConfig.Encryption values: how stored bytes relate to the plaintext a
// client downloads (architecture.md § "storage backend と暗号化").
const (
	// EncryptionNone stores objects in the clear.
	EncryptionNone = "none"
	// EncryptionAtRest stores objects as AES-256-GCM envelopes the server
	// decrypts on delivery; it requires EncryptionKeyFile.
	EncryptionAtRest = "at-rest"
)

// DRSConfig.StorageBackend values: where object bytes live
// (architecture.md § "storage backend と暗号化").
const (
	// StorageFilesystem DRS-ifies existing directories read-only, configured by
	// the manifest.
	StorageFilesystem = "filesystem"
	// StorageS3 stores objects in an S3 bucket (SeaweedFS) and can receive
	// uploads, carrying each object's id and dataset in object metadata.
	StorageS3 = "s3"
)

// DRSConfig holds the configuration for the DRS server.
type DRSConfig struct {
	// Addr is the listen address, e.g. ":28000".
	Addr string
	// PublicHost is the host used to build DRS URIs (drs://<PublicHost>/<id>),
	// as required by architecture.md § "object ID scheme".
	PublicHost string
	// StorageBackend selects where object bytes live: StorageFilesystem or
	// StorageS3 (architecture.md § "storage backend と暗号化").
	StorageBackend string
	// ManifestPath is the JSON manifest mapping filesystem roots to dataset
	// resource URLs. Required by StorageFilesystem, rejected under StorageS3
	// (which carries the dataset in object metadata).
	ManifestPath string
	// S3Endpoint is the S3 (SeaweedFS) endpoint URL. Required by StorageS3.
	S3Endpoint string
	// S3Region is the S3 region sent with requests. SeaweedFS ignores it but the
	// signer requires one.
	S3Region string
	// S3Bucket is the bucket holding the objects. Required by StorageS3.
	S3Bucket string
	// S3KeyPrefix scopes the backend to keys under it, so a shared bucket stays
	// safe. Optional.
	S3KeyPrefix string
	// S3AccessKey and S3SecretKey are the static credentials used to sign S3
	// requests. Required by StorageS3.
	S3AccessKey string
	S3SecretKey string
	// S3ForcePathStyle selects path-style addressing, which SeaweedFS requires.
	S3ForcePathStyle bool
	// IndexDBPath is the SQLite derived-index path, rebuilt from storage at
	// startup (architecture.md § "index").
	IndexDBPath string
	// ServiceID is the service-info id, e.g. "jp.ac.nig.ddbj.humandbs-drs".
	ServiceID string
	// ServiceName is the human-readable service-info name.
	ServiceName string
	// OrgName is the service-info organization name.
	OrgName string
	// OrgURL is the service-info organization URL.
	OrgURL string
	// TrustedIssuers are the issuers whose passports and visas the
	// Clearinghouse accepts, each with the JWKS URL its keys are pinned from.
	// Their issuer URLs are advertised as passport_auth_issuers in the OPTIONS
	// Authorizations (architecture.md § "Clearinghouse 設計").
	TrustedIssuers []TrustedIssuer
	// SessionTTL is the lifetime of a delivery session token: short, so a
	// revoked grant stops mattering within minutes even without an explicit
	// revoke (architecture.md § "配信設計").
	SessionTTL time.Duration
	// AdminToken authenticates the internal POST /admin/revoke control-plane
	// call. Empty disables revocation (the endpoint answers 503), so it is
	// fail-closed (architecture.md § "配信設計").
	AdminToken string
	// Encryption selects the encryption provider: EncryptionNone or
	// EncryptionAtRest.
	Encryption string
	// EncryptionKeyFile is the hex key file of the at-rest key. Required by
	// EncryptionAtRest and rejected under EncryptionNone, so a configuration
	// cannot silently serve ciphertext or ignore a key it was handed.
	EncryptionKeyFile string
}

// IssuerConfig holds the configuration for the Visa issuer.
type IssuerConfig struct {
	// Addr is the listen address, e.g. ":28001".
	Addr string
	// PublicURL is the issuer's public URL, used as the visa `iss` claim and
	// as the base for the JWKS `jku`, per architecture.md § "Issuer 設計".
	PublicURL string
	// OIDCIssuer is the URL of the OIDC provider (Keycloak realm) whose access
	// tokens the issuer accepts.
	OIDCIssuer string
	// OIDCClientID, when non-empty, must appear in the access token audience.
	// Empty skips the audience check.
	OIDCClientID string
	// SigningKeyPath is the PEM file holding the visa signing key. A missing
	// file is created with a fresh key on startup.
	SigningKeyPath string
	// GrantDBPath is the SQLite grant database path.
	GrantDBPath string
	// VisaTTL caps the lifetime of minted visas
	// (architecture.md § "Issuer 設計").
	VisaTTL time.Duration
	// SeedPath, when non-empty, is a JSON grant file loaded into the grant DB
	// at startup.
	SeedPath string
}

const (
	envDRSAddr              = "HUMANDBS_DRS_ADDR"
	envDRSPublicHost        = "HUMANDBS_DRS_PUBLIC_HOST"
	envDRSStorageBackend    = "HUMANDBS_DRS_STORAGE_BACKEND"
	envDRSManifest          = "HUMANDBS_DRS_MANIFEST"
	envDRSS3Endpoint        = "HUMANDBS_DRS_S3_ENDPOINT"
	envDRSS3Region          = "HUMANDBS_DRS_S3_REGION"
	envDRSS3Bucket          = "HUMANDBS_DRS_S3_BUCKET"
	envDRSS3KeyPrefix       = "HUMANDBS_DRS_S3_KEY_PREFIX"
	envDRSS3AccessKey       = "HUMANDBS_DRS_S3_ACCESS_KEY"
	envDRSS3SecretKey       = "HUMANDBS_DRS_S3_SECRET_KEY"
	envDRSS3ForcePathStyle  = "HUMANDBS_DRS_S3_FORCE_PATH_STYLE"
	envDRSIndexDB           = "HUMANDBS_DRS_INDEX_DB"
	envDRSServiceID         = "HUMANDBS_DRS_SERVICE_ID"
	envDRSServiceName       = "HUMANDBS_DRS_SERVICE_NAME"
	envDRSOrgName           = "HUMANDBS_DRS_ORG_NAME"
	envDRSOrgURL            = "HUMANDBS_DRS_ORG_URL"
	envDRSTrustedIssuers    = "HUMANDBS_DRS_TRUSTED_ISSUERS"
	envDRSSessionTTL        = "HUMANDBS_DRS_SESSION_TTL"
	envDRSAdminToken        = "HUMANDBS_DRS_ADMIN_TOKEN"
	envDRSEncryption        = "HUMANDBS_DRS_ENCRYPTION"
	envDRSEncryptionKeyFile = "HUMANDBS_DRS_ENCRYPTION_KEY_FILE"

	envIssuerAddr         = "HUMANDBS_ISSUER_ADDR"
	envIssuerPublicURL    = "HUMANDBS_ISSUER_PUBLIC_URL"
	envIssuerOIDCIssuer   = "HUMANDBS_ISSUER_OIDC_ISSUER"
	envIssuerOIDCClientID = "HUMANDBS_ISSUER_OIDC_CLIENT_ID"
	envIssuerSigningKey   = "HUMANDBS_ISSUER_SIGNING_KEY"
	envIssuerGrantDB      = "HUMANDBS_ISSUER_GRANT_DB"
	envIssuerVisaTTL      = "HUMANDBS_ISSUER_VISA_TTL"
	envIssuerSeed         = "HUMANDBS_ISSUER_SEED"

	defaultDRSAddr          = ":28000"
	defaultIssuerAddr       = ":28001"
	defaultVisaTTL          = "1h"
	defaultSessionTTL       = "5m"
	defaultStorageBackend   = StorageFilesystem
	defaultS3Region         = "us-east-1"
	defaultS3ForcePathStyle = "true"
)

// MissingError reports required configuration fields that resolved to empty.
type MissingError struct {
	Fields []string
}

func (e *MissingError) Error() string {
	return "missing required configuration: " + strings.Join(e.Fields, ", ")
}

// DRSFlags binds DRS configuration flags to a flag set.
type DRSFlags struct {
	addr              *string
	publicHost        *string
	storageBackend    *string
	manifest          *string
	s3Endpoint        *string
	s3Region          *string
	s3Bucket          *string
	s3KeyPrefix       *string
	s3AccessKey       *string
	s3SecretKey       *string
	s3ForcePathStyle  *string
	indexDB           *string
	serviceID         *string
	serviceName       *string
	orgName           *string
	orgURL            *string
	trustedIssuers    *string
	sessionTTL        *string
	adminToken        *string
	encryption        *string
	encryptionKeyFile *string
}

// RegisterDRSFlags registers the DRS configuration flags on fs. The caller
// parses fs, then calls Resolve to obtain the configuration.
func RegisterDRSFlags(fs *flag.FlagSet) *DRSFlags {
	return &DRSFlags{
		addr:              fs.String("addr", "", "listen address (default "+defaultDRSAddr+")"),
		publicHost:        fs.String("public-host", "", "host for DRS URIs drs://<host>/<id> (required)"),
		storageBackend:    fs.String("storage-backend", "", "storage backend, "+StorageFilesystem+" or "+StorageS3+" (default "+defaultStorageBackend+")"),
		manifest:          fs.String("manifest", "", "JSON manifest of filesystem roots to dataset URLs (required with -storage-backend "+StorageFilesystem+")"),
		s3Endpoint:        fs.String("s3-endpoint", "", "S3 (SeaweedFS) endpoint URL (required with -storage-backend "+StorageS3+")"),
		s3Region:          fs.String("s3-region", "", "S3 region (default "+defaultS3Region+")"),
		s3Bucket:          fs.String("s3-bucket", "", "S3 bucket holding the objects (required with -storage-backend "+StorageS3+")"),
		s3KeyPrefix:       fs.String("s3-key-prefix", "", "S3 key prefix scoping the backend (optional)"),
		s3AccessKey:       fs.String("s3-access-key", "", "S3 access key (required with -storage-backend "+StorageS3+")"),
		s3SecretKey:       fs.String("s3-secret-key", "", "S3 secret key (required with -storage-backend "+StorageS3+")"),
		s3ForcePathStyle:  fs.String("s3-force-path-style", "", "use path-style S3 addressing, required by SeaweedFS (default "+defaultS3ForcePathStyle+")"),
		indexDB:           fs.String("index-db", "", "SQLite derived-index path, rebuilt at startup (required)"),
		serviceID:         fs.String("service-id", "", "service-info id, e.g. jp.ac.nig.ddbj.humandbs-drs (required)"),
		serviceName:       fs.String("service-name", "", "service-info human-readable name (required)"),
		orgName:           fs.String("org-name", "", "service-info organization name (required)"),
		orgURL:            fs.String("org-url", "", "service-info organization URL (required)"),
		trustedIssuers:    fs.String("trusted-issuer", "", "comma-separated <issuer URL>=<JWKS URL> pairs of trusted visa issuers (required)"),
		sessionTTL:        fs.String("session-ttl", "", "delivery session token lifetime as a Go duration (default "+defaultSessionTTL+")"),
		adminToken:        fs.String("admin-token", "", "shared secret authenticating POST /admin/revoke; empty disables revocation (optional)"),
		encryption:        fs.String("encryption", "", "encryption provider, "+EncryptionNone+" or "+EncryptionAtRest+" (default "+EncryptionNone+")"),
		encryptionKeyFile: fs.String("encryption-key-file", "", "hex file of the 32-byte at-rest key (required with -encryption "+EncryptionAtRest+")"),
	}
}

// Resolve produces a DRSConfig from the parsed flags and the environment.
func (f *DRSFlags) Resolve(fs *flag.FlagSet, getenv func(string) string) (DRSConfig, error) {
	set := setFlags(fs)
	trustedIssuers, err := parseTrustedIssuers(resolve(set, "trusted-issuer", *f.trustedIssuers, getenv(envDRSTrustedIssuers), ""))
	if err != nil {
		return DRSConfig{}, err
	}
	cfg := DRSConfig{
		Addr:           resolve(set, "addr", *f.addr, getenv(envDRSAddr), defaultDRSAddr),
		PublicHost:     resolve(set, "public-host", *f.publicHost, getenv(envDRSPublicHost), ""),
		StorageBackend: resolve(set, "storage-backend", *f.storageBackend, getenv(envDRSStorageBackend), defaultStorageBackend),
		ManifestPath:   resolve(set, "manifest", *f.manifest, getenv(envDRSManifest), ""),
		S3Endpoint:     resolve(set, "s3-endpoint", *f.s3Endpoint, getenv(envDRSS3Endpoint), ""),
		S3Region:       resolve(set, "s3-region", *f.s3Region, getenv(envDRSS3Region), defaultS3Region),
		S3Bucket:       resolve(set, "s3-bucket", *f.s3Bucket, getenv(envDRSS3Bucket), ""),
		S3KeyPrefix:    resolve(set, "s3-key-prefix", *f.s3KeyPrefix, getenv(envDRSS3KeyPrefix), ""),
		S3AccessKey:    resolve(set, "s3-access-key", *f.s3AccessKey, getenv(envDRSS3AccessKey), ""),
		S3SecretKey:    resolve(set, "s3-secret-key", *f.s3SecretKey, getenv(envDRSS3SecretKey), ""),
		IndexDBPath:    resolve(set, "index-db", *f.indexDB, getenv(envDRSIndexDB), ""),
		ServiceID:      resolve(set, "service-id", *f.serviceID, getenv(envDRSServiceID), ""),
		ServiceName:    resolve(set, "service-name", *f.serviceName, getenv(envDRSServiceName), ""),
		OrgName:        resolve(set, "org-name", *f.orgName, getenv(envDRSOrgName), ""),
		OrgURL:         resolve(set, "org-url", *f.orgURL, getenv(envDRSOrgURL), ""),
		TrustedIssuers: trustedIssuers,
		AdminToken:     resolve(set, "admin-token", *f.adminToken, getenv(envDRSAdminToken), ""),
	}

	forcePathStyle := resolve(set, "s3-force-path-style", *f.s3ForcePathStyle, getenv(envDRSS3ForcePathStyle), defaultS3ForcePathStyle)
	fps, err := strconv.ParseBool(forcePathStyle)
	if err != nil {
		return DRSConfig{}, fmt.Errorf("invalid s3-force-path-style %q: %w", forcePathStyle, err)
	}
	cfg.S3ForcePathStyle = fps

	var missing []string
	if cfg.Addr == "" {
		missing = append(missing, "addr")
	}
	if cfg.PublicHost == "" {
		missing = append(missing, "public-host")
	}
	switch cfg.StorageBackend {
	case StorageFilesystem:
		if cfg.ManifestPath == "" {
			missing = append(missing, "manifest")
		}
	case StorageS3:
		if cfg.ManifestPath != "" {
			return DRSConfig{}, fmt.Errorf("manifest is set but storage-backend is %q", StorageS3)
		}
		if cfg.S3Endpoint == "" {
			missing = append(missing, "s3-endpoint")
		}
		if cfg.S3Bucket == "" {
			missing = append(missing, "s3-bucket")
		}
		if cfg.S3AccessKey == "" {
			missing = append(missing, "s3-access-key")
		}
		if cfg.S3SecretKey == "" {
			missing = append(missing, "s3-secret-key")
		}
	default:
		return DRSConfig{}, fmt.Errorf("invalid storage-backend %q: want %q or %q", cfg.StorageBackend, StorageFilesystem, StorageS3)
	}
	if cfg.IndexDBPath == "" {
		missing = append(missing, "index-db")
	}
	if cfg.ServiceID == "" {
		missing = append(missing, "service-id")
	}
	if cfg.ServiceName == "" {
		missing = append(missing, "service-name")
	}
	if cfg.OrgName == "" {
		missing = append(missing, "org-name")
	}
	if cfg.OrgURL == "" {
		missing = append(missing, "org-url")
	}
	if len(cfg.TrustedIssuers) == 0 {
		missing = append(missing, "trusted-issuer")
	}
	if len(missing) > 0 {
		return DRSConfig{}, &MissingError{Fields: missing}
	}

	ttlValue := resolve(set, "session-ttl", *f.sessionTTL, getenv(envDRSSessionTTL), defaultSessionTTL)
	ttl, err := time.ParseDuration(ttlValue)
	if err != nil {
		return DRSConfig{}, fmt.Errorf("invalid session-ttl %q: %w", ttlValue, err)
	}
	if ttl <= 0 {
		return DRSConfig{}, fmt.Errorf("session-ttl must be positive, got %s", ttl)
	}
	cfg.SessionTTL = ttl

	enc := resolve(set, "encryption", *f.encryption, getenv(envDRSEncryption), EncryptionNone)
	keyFile := resolve(set, "encryption-key-file", *f.encryptionKeyFile, getenv(envDRSEncryptionKeyFile), "")
	switch enc {
	case EncryptionNone:
		if keyFile != "" {
			return DRSConfig{}, fmt.Errorf("encryption-key-file is set but encryption is %q", EncryptionNone)
		}
	case EncryptionAtRest:
		if keyFile == "" {
			return DRSConfig{}, fmt.Errorf("encryption %q requires encryption-key-file", EncryptionAtRest)
		}
	default:
		return DRSConfig{}, fmt.Errorf("invalid encryption %q: want %q or %q", enc, EncryptionNone, EncryptionAtRest)
	}
	cfg.Encryption = enc
	cfg.EncryptionKeyFile = keyFile

	return cfg, nil
}

// IssuerFlags binds Visa issuer configuration flags to a flag set.
type IssuerFlags struct {
	addr         *string
	publicURL    *string
	oidcIssuer   *string
	oidcClientID *string
	signingKey   *string
	grantDB      *string
	visaTTL      *string
	seed         *string
}

// RegisterIssuerFlags registers the issuer configuration flags on fs. The
// caller parses fs, then calls Resolve to obtain the configuration.
func RegisterIssuerFlags(fs *flag.FlagSet) *IssuerFlags {
	return &IssuerFlags{
		addr:         fs.String("addr", "", "listen address (default "+defaultIssuerAddr+")"),
		publicURL:    fs.String("public-url", "", "issuer public URL, used as visa iss and jku base (required)"),
		oidcIssuer:   fs.String("oidc-issuer", "", "OIDC provider URL whose access tokens are accepted (required)"),
		oidcClientID: fs.String("oidc-client-id", "", "required audience of access tokens (empty skips the check)"),
		signingKey:   fs.String("signing-key", "", "PEM file of the visa signing key, created when absent (required)"),
		grantDB:      fs.String("grant-db", "", "SQLite grant database path (required)"),
		visaTTL:      fs.String("visa-ttl", "", "visa lifetime cap as a Go duration (default "+defaultVisaTTL+")"),
		seed:         fs.String("seed", "", "JSON grant file loaded at startup (optional)"),
	}
}

// Resolve produces an IssuerConfig from the parsed flags and the environment.
func (f *IssuerFlags) Resolve(fs *flag.FlagSet, getenv func(string) string) (IssuerConfig, error) {
	set := setFlags(fs)
	cfg := IssuerConfig{
		Addr:           resolve(set, "addr", *f.addr, getenv(envIssuerAddr), defaultIssuerAddr),
		PublicURL:      resolve(set, "public-url", *f.publicURL, getenv(envIssuerPublicURL), ""),
		OIDCIssuer:     resolve(set, "oidc-issuer", *f.oidcIssuer, getenv(envIssuerOIDCIssuer), ""),
		OIDCClientID:   resolve(set, "oidc-client-id", *f.oidcClientID, getenv(envIssuerOIDCClientID), ""),
		SigningKeyPath: resolve(set, "signing-key", *f.signingKey, getenv(envIssuerSigningKey), ""),
		GrantDBPath:    resolve(set, "grant-db", *f.grantDB, getenv(envIssuerGrantDB), ""),
		SeedPath:       resolve(set, "seed", *f.seed, getenv(envIssuerSeed), ""),
	}

	var missing []string
	if cfg.Addr == "" {
		missing = append(missing, "addr")
	}
	if cfg.PublicURL == "" {
		missing = append(missing, "public-url")
	}
	if cfg.OIDCIssuer == "" {
		missing = append(missing, "oidc-issuer")
	}
	if cfg.SigningKeyPath == "" {
		missing = append(missing, "signing-key")
	}
	if cfg.GrantDBPath == "" {
		missing = append(missing, "grant-db")
	}
	if len(missing) > 0 {
		return IssuerConfig{}, &MissingError{Fields: missing}
	}

	ttlValue := resolve(set, "visa-ttl", *f.visaTTL, getenv(envIssuerVisaTTL), defaultVisaTTL)
	ttl, err := time.ParseDuration(ttlValue)
	if err != nil {
		return IssuerConfig{}, fmt.Errorf("invalid visa-ttl %q: %w", ttlValue, err)
	}
	if ttl <= 0 {
		return IssuerConfig{}, fmt.Errorf("visa-ttl must be positive, got %s", ttl)
	}
	cfg.VisaTTL = ttl

	return cfg, nil
}

// parseTrustedIssuers parses a comma-separated list of <issuer URL>=<JWKS URL>
// pairs, split at the first "=" so a query string in the JWKS URL survives. An
// issuer URL is matched verbatim against token `iss` claims (no trailing-slash
// normalization), must be http(s), and must carry no query or fragment — a "="
// inside the issuer would make the pair ambiguous. Duplicate issuers are
// rejected rather than silently merged. URLs containing a comma cannot be
// expressed in this format.
func parseTrustedIssuers(v string) ([]TrustedIssuer, error) {
	entries := splitList(v)
	issuers := make([]TrustedIssuer, 0, len(entries))
	seen := make(map[string]bool)
	for _, entry := range entries {
		issuer, jwks, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("trusted-issuer entry %q must be <issuer URL>=<JWKS URL>", entry)
		}
		issuer = strings.TrimSpace(issuer)
		jwks = strings.TrimSpace(jwks)

		issuerURL, err := parseHTTPURL(issuer)
		if err != nil {
			return nil, fmt.Errorf("trusted-issuer entry %q: issuer URL: %w", entry, err)
		}
		if issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
			return nil, fmt.Errorf("trusted-issuer entry %q: issuer URL must not carry a query or fragment", entry)
		}
		if _, err := parseHTTPURL(jwks); err != nil {
			return nil, fmt.Errorf("trusted-issuer entry %q: JWKS URL: %w", entry, err)
		}
		if seen[issuer] {
			return nil, fmt.Errorf("duplicate trusted issuer %q", issuer)
		}
		seen[issuer] = true

		issuers = append(issuers, TrustedIssuer{Issuer: issuer, JWKSURL: jwks})
	}

	return issuers, nil
}

// parseHTTPURL requires an absolute http or https URL with a host. Plain http
// stays allowed for local development setups.
func parseHTTPURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", s, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("URL %q must use http or https", s)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL %q has no host", s)
	}

	return u, nil
}

// splitList parses a comma-separated value into trimmed, non-empty items.
func splitList(v string) []string {
	var items []string
	for _, part := range strings.Split(v, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			items = append(items, trimmed)
		}
	}

	return items
}

// setFlags returns the set of flag names that were explicitly provided.
func setFlags(fs *flag.FlagSet) map[string]bool {
	set := make(map[string]bool)
	fs.Visit(func(fl *flag.Flag) {
		set[fl.Name] = true
	})

	return set
}

// resolve applies the precedence explicit flag > environment > default. An
// explicitly set flag wins even when empty, so a required field passed as an
// empty flag is reported as missing rather than silently defaulted.
func resolve(set map[string]bool, name, flagVal, envVal, def string) string {
	if set[name] {
		return flagVal
	}
	if envVal != "" {
		return envVal
	}

	return def
}
