// Command drs runs the DRS 1.5 API, Passport Clearinghouse, and authorized
// byte delivery for controlled-access data.
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
	"syscall"
	"time"

	"github.com/ddbj/humandbs-drs/internal/buildinfo"
	"github.com/ddbj/humandbs-drs/internal/clearinghouse"
	"github.com/ddbj/humandbs-drs/internal/config"
	"github.com/ddbj/humandbs-drs/internal/drs"
	"github.com/ddbj/humandbs-drs/internal/encryption"
	"github.com/ddbj/humandbs-drs/internal/httpx"
	"github.com/ddbj/humandbs-drs/internal/index"
	"github.com/ddbj/humandbs-drs/internal/storage"
	"github.com/ddbj/humandbs-drs/internal/token"
)

const serviceName = "humandbs-drs"

// jwksFetchTimeout bounds each startup JWKS fetch.
const jwksFetchTimeout = 10 * time.Second

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
	flags := config.RegisterDRSFlags(fs)
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

	backend, err := buildBackend(cfg)
	if err != nil {
		return err
	}

	provider, err := buildProvider(cfg)
	if err != nil {
		return err
	}

	idx, err := index.Open(cfg.IndexDBPath)
	if err != nil {
		return err
	}
	defer func() { _ = idx.Close() }()

	n, err := idx.Rebuild(ctx, backend, provider)
	if err != nil {
		return err
	}
	logger.Info("index rebuilt", "objects", n, "encryption", cfg.Encryption)

	ch, advertised, err := buildClearinghouse(ctx, cfg.TrustedIssuers, logger)
	if err != nil {
		return err
	}
	tokens, err := token.NewStore(cfg.SessionTTL)
	if err != nil {
		return err
	}

	drsHandler := drs.NewHandler(idx, backend, ch, tokens, provider, drs.Settings{
		PublicHost:     cfg.PublicHost,
		ServiceID:      cfg.ServiceID,
		ServiceName:    cfg.ServiceName,
		OrgName:        cfg.OrgName,
		OrgURL:         cfg.OrgURL,
		Version:        buildinfo.Version,
		TrustedIssuers: advertised,
		AdminToken:     cfg.AdminToken,
	}, logger)

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", httpx.Health(serviceName, buildinfo.Version))
	// The DRS handler registers full paths (DRS API under BasePath, plus /data
	// and /admin), so it is mounted at the root; /healthz stays more specific.
	mux.Handle("/", drsHandler)

	return httpx.Serve(ctx, cfg.Addr, mux, logger)
}

// buildClearinghouse pins each trusted issuer's keys from its configured JWKS
// URL and returns the Clearinghouse plus the issuer URLs to advertise in
// OPTIONS. Key rotation takes effect on restart
// (architecture.md § "Clearinghouse 設計").
func buildClearinghouse(ctx context.Context, issuers []config.TrustedIssuer, logger *slog.Logger) (*clearinghouse.Clearinghouse, []string, error) {
	trusted := make([]clearinghouse.Issuer, 0, len(issuers))
	advertised := make([]string, 0, len(issuers))
	for _, ti := range issuers {
		fetchCtx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
		keys, err := clearinghouse.FetchKeys(fetchCtx, ti.JWKSURL)
		cancel()
		if err != nil {
			return nil, nil, err
		}
		logger.Info("pinned issuer keys", "issuer", ti.Issuer, "jwks", ti.JWKSURL, "keys", keys.Len())

		trusted = append(trusted, clearinghouse.Issuer{URL: ti.Issuer, JWKSURL: ti.JWKSURL, Keys: keys})
		advertised = append(advertised, ti.Issuer)
	}

	ch, err := clearinghouse.New(trusted, clearinghouse.WithLogger(logger))
	if err != nil {
		return nil, nil, err
	}

	return ch, advertised, nil
}

// buildBackend constructs the storage backend the configuration selects: the
// filesystem backend over the manifest's roots, or the s3 backend over a bucket
// (architecture.md § "storage backend と暗号化"). Both look identical to the
// rest of the server.
func buildBackend(cfg config.DRSConfig) (storage.Backend, error) {
	switch cfg.StorageBackend {
	case config.StorageFilesystem:
		datasets, err := loadManifest(cfg.ManifestPath)
		if err != nil {
			return nil, err
		}

		return storage.NewFSBackend(datasets)
	case config.StorageS3:
		return storage.NewS3Backend(storage.S3Config{
			Endpoint:       cfg.S3Endpoint,
			Region:         cfg.S3Region,
			Bucket:         cfg.S3Bucket,
			KeyPrefix:      cfg.S3KeyPrefix,
			AccessKey:      cfg.S3AccessKey,
			SecretKey:      cfg.S3SecretKey,
			ForcePathStyle: cfg.S3ForcePathStyle,
		})
	default:
		return nil, fmt.Errorf("unknown storage backend %q", cfg.StorageBackend)
	}
}

// buildProvider constructs the encryption provider the configuration selects:
// pass-through, or at-rest decryption under the key file's key
// (architecture.md § "storage backend と暗号化").
func buildProvider(cfg config.DRSConfig) (encryption.Provider, error) {
	switch cfg.Encryption {
	case config.EncryptionNone:
		return encryption.None{}, nil
	case config.EncryptionAtRest:
		key, err := encryption.ReadKeyFile(cfg.EncryptionKeyFile)
		if err != nil {
			return nil, err
		}

		return encryption.NewAtRest(key, encryption.DefaultChunkSize)
	default:
		return nil, fmt.Errorf("unknown encryption %q", cfg.Encryption)
	}
}

// loadManifest reads the dataset manifest from path.
func loadManifest(path string) ([]storage.Dataset, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return storage.ParseManifest(f)
}
