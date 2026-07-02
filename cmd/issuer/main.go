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
	"syscall"

	"github.com/ddbj/humandbs-drs/internal/buildinfo"
	"github.com/ddbj/humandbs-drs/internal/config"
	"github.com/ddbj/humandbs-drs/internal/httpx"
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

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", httpx.Health(serviceName, buildinfo.Version))

	return httpx.Serve(ctx, cfg.Addr, mux, logger)
}
