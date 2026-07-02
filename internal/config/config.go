// Package config resolves process configuration from command-line flags and
// environment variables. Explicit flags take precedence over environment
// variables, which take precedence over built-in defaults. An empty
// environment value is treated as unset.
package config

import (
	"flag"
	"strings"
)

// DRSConfig holds the configuration for the DRS server.
type DRSConfig struct {
	// Addr is the listen address, e.g. ":28000".
	Addr string
	// PublicHost is the host used to build DRS URIs (drs://<PublicHost>/<id>),
	// as required by architecture.md § "object ID scheme".
	PublicHost string
}

// IssuerConfig holds the configuration for the Visa issuer.
type IssuerConfig struct {
	// Addr is the listen address, e.g. ":28001".
	Addr string
	// PublicURL is the issuer's public URL, used as the visa `iss` claim and
	// as the base for the JWKS `jku`, per architecture.md § "Issuer 設計".
	PublicURL string
}

const (
	envDRSAddr       = "HUMANDBS_DRS_ADDR"
	envDRSPublicHost = "HUMANDBS_DRS_PUBLIC_HOST"

	envIssuerAddr      = "HUMANDBS_ISSUER_ADDR"
	envIssuerPublicURL = "HUMANDBS_ISSUER_PUBLIC_URL"

	defaultDRSAddr    = ":28000"
	defaultIssuerAddr = ":28001"
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
	addr       *string
	publicHost *string
}

// RegisterDRSFlags registers the DRS configuration flags on fs. The caller
// parses fs, then calls Resolve to obtain the configuration.
func RegisterDRSFlags(fs *flag.FlagSet) *DRSFlags {
	return &DRSFlags{
		addr:       fs.String("addr", "", "listen address (default "+defaultDRSAddr+")"),
		publicHost: fs.String("public-host", "", "host for DRS URIs drs://<host>/<id> (required)"),
	}
}

// Resolve produces a DRSConfig from the parsed flags and the environment.
func (f *DRSFlags) Resolve(fs *flag.FlagSet, getenv func(string) string) (DRSConfig, error) {
	set := setFlags(fs)
	cfg := DRSConfig{
		Addr:       resolve(set, "addr", *f.addr, getenv(envDRSAddr), defaultDRSAddr),
		PublicHost: resolve(set, "public-host", *f.publicHost, getenv(envDRSPublicHost), ""),
	}

	var missing []string
	if cfg.Addr == "" {
		missing = append(missing, "addr")
	}
	if cfg.PublicHost == "" {
		missing = append(missing, "public-host")
	}
	if len(missing) > 0 {
		return DRSConfig{}, &MissingError{Fields: missing}
	}

	return cfg, nil
}

// IssuerFlags binds Visa issuer configuration flags to a flag set.
type IssuerFlags struct {
	addr      *string
	publicURL *string
}

// RegisterIssuerFlags registers the issuer configuration flags on fs. The
// caller parses fs, then calls Resolve to obtain the configuration.
func RegisterIssuerFlags(fs *flag.FlagSet) *IssuerFlags {
	return &IssuerFlags{
		addr:      fs.String("addr", "", "listen address (default "+defaultIssuerAddr+")"),
		publicURL: fs.String("public-url", "", "issuer public URL, used as visa iss and jku base (required)"),
	}
}

// Resolve produces an IssuerConfig from the parsed flags and the environment.
func (f *IssuerFlags) Resolve(fs *flag.FlagSet, getenv func(string) string) (IssuerConfig, error) {
	set := setFlags(fs)
	cfg := IssuerConfig{
		Addr:      resolve(set, "addr", *f.addr, getenv(envIssuerAddr), defaultIssuerAddr),
		PublicURL: resolve(set, "public-url", *f.publicURL, getenv(envIssuerPublicURL), ""),
	}

	var missing []string
	if cfg.Addr == "" {
		missing = append(missing, "addr")
	}
	if cfg.PublicURL == "" {
		missing = append(missing, "public-url")
	}
	if len(missing) > 0 {
		return IssuerConfig{}, &MissingError{Fields: missing}
	}

	return cfg, nil
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
