package config

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
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

func TestDRSDefaults(t *testing.T) {
	cfg, err := loadDRS(t, nil, map[string]string{
		envDRSPublicHost: "drs.example.org",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != defaultDRSAddr {
		t.Errorf("Addr = %q, want default %q", cfg.Addr, defaultDRSAddr)
	}
	if cfg.PublicHost != "drs.example.org" {
		t.Errorf("PublicHost = %q, want %q", cfg.PublicHost, "drs.example.org")
	}
}

func TestDRSEnvOverridesDefault(t *testing.T) {
	cfg, err := loadDRS(t, nil, map[string]string{
		envDRSAddr:       ":9000",
		envDRSPublicHost: "drs.example.org",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != ":9000" {
		t.Errorf("Addr = %q, want env value %q", cfg.Addr, ":9000")
	}
}

func TestDRSFlagOverridesEnv(t *testing.T) {
	cfg, err := loadDRS(t, []string{"-addr", ":7000", "-public-host", "flag.example.org"}, map[string]string{
		envDRSAddr:       ":9000",
		envDRSPublicHost: "env.example.org",
	})
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
	cfg, err := loadDRS(t, nil, map[string]string{
		envDRSAddr:       "",
		envDRSPublicHost: "drs.example.org",
	})
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
		t.Fatal("expected error for missing public-host, got nil")
	}

	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("error = %v, want *MissingError", err)
	}
	if got := missing.Fields; len(got) != 1 || got[0] != "public-host" {
		t.Errorf("missing fields = %v, want [public-host]", got)
	}
}

// An explicitly empty required flag must fail, not silently pass.
func TestDRSExplicitEmptyRequiredFlagFails(t *testing.T) {
	_, err := loadDRS(t, []string{"-public-host", ""}, nil)

	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("error = %v, want *MissingError", err)
	}
}

func TestIssuerDefaults(t *testing.T) {
	cfg, err := loadIssuer(t, nil, map[string]string{
		envIssuerPublicURL: "https://issuer.example.org",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != defaultIssuerAddr {
		t.Errorf("Addr = %q, want default %q", cfg.Addr, defaultIssuerAddr)
	}
	if cfg.PublicURL != "https://issuer.example.org" {
		t.Errorf("PublicURL = %q, want %q", cfg.PublicURL, "https://issuer.example.org")
	}
}

func TestIssuerFlagOverridesEnv(t *testing.T) {
	cfg, err := loadIssuer(t, []string{"-public-url", "https://flag.example.org"}, map[string]string{
		envIssuerPublicURL: "https://env.example.org",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PublicURL != "https://flag.example.org" {
		t.Errorf("PublicURL = %q, want flag value %q", cfg.PublicURL, "https://flag.example.org")
	}
}

func TestIssuerMissingRequired(t *testing.T) {
	_, err := loadIssuer(t, nil, nil)

	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("error = %v, want *MissingError", err)
	}
	if got := missing.Fields; len(got) != 1 || got[0] != "public-url" {
		t.Errorf("missing fields = %v, want [public-url]", got)
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
