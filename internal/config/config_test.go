package config

import (
	"errors"
	"flag"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

// env builds a getenv func backed by a fixed map so tests inject the
// environment boundary instead of mutating the process environment.
func env(pairs map[string]string) func(string) string {
	return func(key string) string {
		return pairs[key]
	}
}

func loadDRS(t *testing.T, args []string, environ map[string]string) (DRSConfig, error) {
	t.Helper()

	fs := flag.NewFlagSet("drs", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	df := RegisterDRSFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse args %v: %v", args, err)
	}

	return df.Resolve(fs, env(environ))
}

func loadIssuer(t *testing.T, args []string, environ map[string]string) (IssuerConfig, error) {
	t.Helper()

	fs := flag.NewFlagSet("issuer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	inf := RegisterIssuerFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse args %v: %v", args, err)
	}

	return inf.Resolve(fs, env(environ))
}

// validDRSEnv sets every required DRS field via the environment, so a test can
// override just the field it exercises without tripping the missing-required
// check.
func validDRSEnv() map[string]string {
	return map[string]string{
		envDRSPublicHost:     "drs.example.org",
		envDRSManifest:       "/tmp/manifest.json",
		envDRSIndexDB:        "/tmp/index.db",
		envDRSServiceID:      "jp.ac.nig.ddbj.humandbs-drs",
		envDRSServiceName:    "HumanDBs DRS",
		envDRSOrgName:        "DDBJ",
		envDRSOrgURL:         "https://www.ddbj.nig.ac.jp/",
		envDRSTrustedIssuers: "https://issuer.example.org=https://issuer.example.org/jwks",
	}
}

func TestDRSDefaults(t *testing.T) {
	cfg, err := loadDRS(t, nil, validDRSEnv())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != defaultDRSAddr {
		t.Errorf("Addr = %q, want default %q", cfg.Addr, defaultDRSAddr)
	}
	if cfg.PublicHost != "drs.example.org" {
		t.Errorf("PublicHost = %q, want %q", cfg.PublicHost, "drs.example.org")
	}
	if cfg.ServiceID != "jp.ac.nig.ddbj.humandbs-drs" {
		t.Errorf("ServiceID = %q, want %q", cfg.ServiceID, "jp.ac.nig.ddbj.humandbs-drs")
	}
	want := TrustedIssuer{Issuer: "https://issuer.example.org", JWKSURL: "https://issuer.example.org/jwks"}
	if len(cfg.TrustedIssuers) != 1 || cfg.TrustedIssuers[0] != want {
		t.Errorf("TrustedIssuers = %v, want [%v]", cfg.TrustedIssuers, want)
	}
}

func TestDRSSessionTTLAndAdminTokenDefaults(t *testing.T) {
	cfg, err := loadDRS(t, nil, validDRSEnv())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SessionTTL != 5*time.Minute {
		t.Errorf("SessionTTL = %s, want default 5m", cfg.SessionTTL)
	}
	if cfg.AdminToken != "" {
		t.Errorf("AdminToken = %q, want empty (revocation off)", cfg.AdminToken)
	}
}

func TestDRSSessionTTLAndAdminTokenResolve(t *testing.T) {
	environ := validDRSEnv()
	environ[envDRSSessionTTL] = "30m"
	environ[envDRSAdminToken] = "env-secret"
	cfg, err := loadDRS(t, []string{"-session-ttl", "90s", "-admin-token", "flag-secret"}, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SessionTTL != 90*time.Second {
		t.Errorf("SessionTTL = %s, want flag value 90s", cfg.SessionTTL)
	}
	if cfg.AdminToken != "flag-secret" {
		t.Errorf("AdminToken = %q, want flag value %q", cfg.AdminToken, "flag-secret")
	}
}

func TestDRSSessionTTLFromEnv(t *testing.T) {
	environ := validDRSEnv()
	environ[envDRSSessionTTL] = "10m"
	cfg, err := loadDRS(t, nil, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SessionTTL != 10*time.Minute {
		t.Errorf("SessionTTL = %s, want env value 10m", cfg.SessionTTL)
	}
}

func TestDRSRejectsBadSessionTTL(t *testing.T) {
	for _, ttl := range []string{"nonsense", "0s", "-1m"} {
		t.Run(ttl, func(t *testing.T) {
			environ := validDRSEnv()
			environ[envDRSSessionTTL] = ttl
			if _, err := loadDRS(t, nil, environ); err == nil {
				t.Fatalf("want error for session-ttl %q, got nil", ttl)
			}
		})
	}
}

func TestDRSEnvOverridesDefault(t *testing.T) {
	environ := validDRSEnv()
	environ[envDRSAddr] = ":9000"
	cfg, err := loadDRS(t, nil, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != ":9000" {
		t.Errorf("Addr = %q, want env value %q", cfg.Addr, ":9000")
	}
}

func TestDRSFlagOverridesEnv(t *testing.T) {
	environ := validDRSEnv()
	environ[envDRSAddr] = ":9000"
	environ[envDRSPublicHost] = "env.example.org"
	cfg, err := loadDRS(t, []string{"-addr", ":7000", "-public-host", "flag.example.org"}, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != ":7000" {
		t.Errorf("Addr = %q, want flag value %q", cfg.Addr, ":7000")
	}
	if cfg.PublicHost != "flag.example.org" {
		t.Errorf("PublicHost = %q, want flag value %q", cfg.PublicHost, "flag.example.org")
	}
}

// An empty environment value must be treated as unset so the default wins,
// rather than resolving the field to an empty string.
func TestDRSEmptyEnvFallsBackToDefault(t *testing.T) {
	environ := validDRSEnv()
	environ[envDRSAddr] = ""
	cfg, err := loadDRS(t, nil, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != defaultDRSAddr {
		t.Errorf("Addr = %q, want default %q", cfg.Addr, defaultDRSAddr)
	}
}

func TestDRSMissingRequired(t *testing.T) {
	_, err := loadDRS(t, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing required fields, got nil")
	}

	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("error = %v, want *MissingError", err)
	}
	got := strings.Join(missing.Fields, ",")
	want := "public-host,manifest,index-db,service-id,service-name,org-name,org-url,trusted-issuer"
	if got != want {
		t.Errorf("missing fields = %q, want %q", got, want)
	}
}

// An explicitly empty required flag must fail even when the environment would
// otherwise supply the value.
func TestDRSExplicitEmptyRequiredFlagFails(t *testing.T) {
	_, err := loadDRS(t, []string{"-public-host", ""}, validDRSEnv())

	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("error = %v, want *MissingError", err)
	}
}

// A comma-separated trusted-issuer resolves to a trimmed, non-empty list of
// issuer/JWKS pairs, split at the first "=" so a query in the JWKS URL
// survives.
func TestDRSTrustedIssuersSplit(t *testing.T) {
	environ := validDRSEnv()
	environ[envDRSTrustedIssuers] = "https://a.example.org=https://a.example.org/jwks, https://b.example.org=https://keys.example.org/jwks?tenant=b ,,https://c.example.org=https://c.example.org/jwks"
	cfg, err := loadDRS(t, nil, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []TrustedIssuer{
		{Issuer: "https://a.example.org", JWKSURL: "https://a.example.org/jwks"},
		{Issuer: "https://b.example.org", JWKSURL: "https://keys.example.org/jwks?tenant=b"},
		{Issuer: "https://c.example.org", JWKSURL: "https://c.example.org/jwks"},
	}
	if len(cfg.TrustedIssuers) != len(want) {
		t.Fatalf("TrustedIssuers = %v, want %v", cfg.TrustedIssuers, want)
	}
	for i := range want {
		if cfg.TrustedIssuers[i] != want[i] {
			t.Errorf("TrustedIssuers[%d] = %v, want %v", i, cfg.TrustedIssuers[i], want[i])
		}
	}
}

// A malformed trusted-issuer entry is a configuration error, not a silently
// dropped item.
func TestDRSTrustedIssuersRejectsMalformedEntries(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"missing separator", "https://issuer.example.org"},
		{"empty issuer", "=https://issuer.example.org/jwks"},
		{"empty jwks", "https://issuer.example.org="},
		{"issuer not a URL", "not a url=https://issuer.example.org/jwks"},
		{"issuer without host", "https://=https://issuer.example.org/jwks"},
		{"issuer wrong scheme", "ftp://issuer.example.org=https://issuer.example.org/jwks"},
		{"jwks wrong scheme", "https://issuer.example.org=file:///etc/jwks.json"},
		{"issuer with query", "https://issuer.example.org/?a=b=https://issuer.example.org/jwks"},
		{"duplicate issuer", "https://issuer.example.org=https://a/jwks,https://issuer.example.org=https://b/jwks"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			environ := validDRSEnv()
			environ[envDRSTrustedIssuers] = tc.value
			if _, err := loadDRS(t, nil, environ); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// A trusted-issuer of only separators and blanks resolves to no issuers and is
// reported as missing.
func TestDRSBlankTrustedIssuerIsMissing(t *testing.T) {
	environ := validDRSEnv()
	environ[envDRSTrustedIssuers] = " , ,"
	_, err := loadDRS(t, nil, environ)
	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("error = %v, want *MissingError", err)
	}
	if len(missing.Fields) != 1 || missing.Fields[0] != "trusted-issuer" {
		t.Errorf("missing fields = %v, want [trusted-issuer]", missing.Fields)
	}
}

func TestDRSServiceIDFlagOverridesEnv(t *testing.T) {
	environ := validDRSEnv()
	environ[envDRSServiceID] = "env.id"
	cfg, err := loadDRS(t, []string{"-service-id", "flag.id"}, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServiceID != "flag.id" {
		t.Errorf("ServiceID = %q, want %q", cfg.ServiceID, "flag.id")
	}
}

// validIssuerEnv covers every required issuer field via the environment, so
// tests tweak only what they exercise.
func validIssuerEnv() map[string]string {
	return map[string]string{
		envIssuerPublicURL:  "https://issuer.example.org",
		envIssuerOIDCIssuer: "https://keycloak.example.org/realms/humandbs",
		envIssuerSigningKey: "/keys/signing.pem",
		envIssuerGrantDB:    "/data/grants.db",
	}
}

func TestIssuerDefaults(t *testing.T) {
	cfg, err := loadIssuer(t, nil, validIssuerEnv())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != defaultIssuerAddr {
		t.Errorf("Addr = %q, want default %q", cfg.Addr, defaultIssuerAddr)
	}
	if cfg.PublicURL != "https://issuer.example.org" {
		t.Errorf("PublicURL = %q, want %q", cfg.PublicURL, "https://issuer.example.org")
	}
	if cfg.VisaTTL != time.Hour {
		t.Errorf("VisaTTL = %s, want default 1h", cfg.VisaTTL)
	}
	if cfg.OIDCClientID != "" {
		t.Errorf("OIDCClientID = %q, want empty (audience check off)", cfg.OIDCClientID)
	}
	if cfg.SeedPath != "" {
		t.Errorf("SeedPath = %q, want empty", cfg.SeedPath)
	}
}

func TestIssuerFlagOverridesEnv(t *testing.T) {
	environ := validIssuerEnv()
	environ[envIssuerVisaTTL] = "30m"
	cfg, err := loadIssuer(t, []string{"-public-url", "https://flag.example.org", "-visa-ttl", "15m"}, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PublicURL != "https://flag.example.org" {
		t.Errorf("PublicURL = %q, want flag value %q", cfg.PublicURL, "https://flag.example.org")
	}
	if cfg.VisaTTL != 15*time.Minute {
		t.Errorf("VisaTTL = %s, want flag value 15m", cfg.VisaTTL)
	}
}

func TestIssuerVisaTTLFromEnv(t *testing.T) {
	environ := validIssuerEnv()
	environ[envIssuerVisaTTL] = "30m"
	cfg, err := loadIssuer(t, nil, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.VisaTTL != 30*time.Minute {
		t.Errorf("VisaTTL = %s, want env value 30m", cfg.VisaTTL)
	}
}

func TestIssuerRejectsBadVisaTTL(t *testing.T) {
	for _, ttl := range []string{"nonsense", "0s", "-5m"} {
		t.Run(ttl, func(t *testing.T) {
			environ := validIssuerEnv()
			environ[envIssuerVisaTTL] = ttl
			if _, err := loadIssuer(t, nil, environ); err == nil {
				t.Fatalf("want error for visa-ttl %q, got nil", ttl)
			}
		})
	}
}

func TestIssuerMissingRequired(t *testing.T) {
	_, err := loadIssuer(t, nil, nil)

	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("error = %v, want *MissingError", err)
	}
	want := []string{"public-url", "oidc-issuer", "signing-key", "grant-db"}
	if got := missing.Fields; !slices.Equal(got, want) {
		t.Errorf("missing fields = %v, want %v", got, want)
	}
}

func TestMissingErrorListsAllFields(t *testing.T) {
	err := &MissingError{Fields: []string{"addr", "public-host"}}
	got := err.Error()
	for _, field := range []string{"addr", "public-host"} {
		if !strings.Contains(got, field) {
			t.Errorf("Error() = %q, want it to mention %q", got, field)
		}
	}
}
