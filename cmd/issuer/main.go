// Command issuer runs the Visa issuer: it manages grants and signs GA4GH
// Passport visas for authenticated users.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ddbj/humandbs-drs/internal/buildinfo"
	"github.com/ddbj/humandbs-drs/internal/config"
	"github.com/ddbj/humandbs-drs/internal/httpx"
	"github.com/ddbj/humandbs-drs/internal/issuer"
	"github.com/ddbj/humandbs-drs/internal/visa"
)

const serviceName = "humandbs-issuer"

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, stdout io.Writer) error {
	fs := flag.NewFlagSet(serviceName, flag.ContinueOnError)
	fs.SetOutput(stdout)
	showVersion := fs.Bool("version", false, "print version and exit")
	flags := config.RegisterIssuerFlags(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}

	if *showVersion {
		_, err := fmt.Fprintln(stdout, serviceName+" "+buildinfo.String())

		return err
	}

	cfg, err := flags.Resolve(fs, getenv)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	key, err := issuer.LoadOrCreateSigningKey(cfg.SigningKeyPath)
	if err != nil {
		return err
	}
	kid, err := issuer.KeyID(&key.PublicKey)
	if err != nil {
		return err
	}
	jku := strings.TrimSuffix(cfg.PublicURL, "/") + "/jwks"
	signer, err := visa.NewSigner(key, kid, jku)
	if err != nil {
		return err
	}
	passport, err := issuer.NewPassportIssuer(signer, cfg.PublicURL, cfg.VisaTTL)
	if err != nil {
		return err
	}
	keys, err := visa.PublicJWKS(visa.KeyEntry{KeyID: kid, Public: &key.PublicKey})
	if err != nil {
		return err
	}
	jwksJSON, err := visa.MarshalJWKS(keys)
	if err != nil {
		return err
	}

	store, err := issuer.OpenGrantStore(cfg.GrantDBPath)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	if cfg.SeedPath != "" {
		count, err := seedGrants(ctx, store, cfg.SeedPath)
		if err != nil {
			return err
		}
		logger.Info("seeded grants", "count", count, "path", cfg.SeedPath)
	}

	verifier, err := issuer.NewOIDCVerifier(ctx, cfg.OIDCIssuer, cfg.OIDCClientID)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", httpx.Health(serviceName, buildinfo.Version))
	mux.Handle("/", issuer.NewHandler(verifier, store, passport, jwksJSON, logger))

	return httpx.Serve(ctx, cfg.Addr, mux, logger)
}

// seedGrants loads the JSON grant file at path into store and reports how many
// grants it stored.
func seedGrants(ctx context.Context, store *issuer.GrantStore, path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open seed file: %w", err)
	}
	defer func() { _ = f.Close() }()

	grants, err := issuer.ParseSeed(f)
	if err != nil {
		return 0, err
	}
	if err := store.Seed(ctx, grants); err != nil {
		return 0, err
	}

	return len(grants), nil
}
