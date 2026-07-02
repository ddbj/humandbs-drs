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
		envDRSTrustedIssuers: "https://issuer.example.org",
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
	if len(cfg.TrustedIssuers) != 1 || cfg.TrustedIssuers[0] != "https://issuer.example.org" {
		t.Errorf("TrustedIssuers = %v, want [https://issuer.example.org]", cfg.TrustedIssuers)
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

// A comma-separated trusted-issuer resolves to a trimmed, non-empty list.
func TestDRSTrustedIssuersSplit(t *testing.T) {
	environ := validDRSEnv()
	environ[envDRSTrustedIssuers] = "https://a.example.org, https://b.example.org ,,https://c.example.org"
	cfg, err := loadDRS(t, nil, environ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := strings.Join(cfg.TrustedIssuers, "|")
	want := "https://a.example.org|https://b.example.org|https://c.example.org"
	if got != want {
		t.Errorf("TrustedIssuers = %q, want %q", got, want)
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
