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

	"github.com/ddbj/humandbs-drs/internal/buildinfo"
	"github.com/ddbj/humandbs-drs/internal/config"
	"github.com/ddbj/humandbs-drs/internal/drs"
	"github.com/ddbj/humandbs-drs/internal/httpx"
	"github.com/ddbj/humandbs-drs/internal/index"
	"github.com/ddbj/humandbs-drs/internal/storage"
)

const serviceName = "humandbs-drs"

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

	datasets, err := loadManifest(cfg.ManifestPath)
	if err != nil {
		return err
	}
	backend, err := storage.NewFSBackend(datasets)
	if err != nil {
		return err
	}

	idx, err := index.Open(cfg.IndexDBPath)
	if err != nil {
		return err
	}
	defer func() { _ = idx.Close() }()

	n, err := idx.Rebuild(ctx, backend)
	if err != nil {
		return err
	}
	logger.Info("index rebuilt", "objects", n)

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", httpx.Health(serviceName, buildinfo.Version))
	mux.Handle(drs.BasePath+"/", drs.NewHandler(idx, drs.Settings{
		PublicHost:     cfg.PublicHost,
		ServiceID:      cfg.ServiceID,
		ServiceName:    cfg.ServiceName,
		OrgName:        cfg.OrgName,
		OrgURL:         cfg.OrgURL,
		Version:        buildinfo.Version,
		TrustedIssuers: cfg.TrustedIssuers,
	}, logger))

	return httpx.Serve(ctx, cfg.Addr, mux, logger)
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
