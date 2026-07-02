// Package httpx provides small HTTP server helpers shared by the binaries.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

const shutdownTimeout = 10 * time.Second

// Serve runs an HTTP server on addr until ctx is cancelled, then shuts it down
// gracefully within a bounded timeout. A server-closed result is not an error.
func Serve(ctx context.Context, addr string, handler http.Handler, logger *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: shutdownTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", addr)
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	return srv.Shutdown(shutdownCtx)
}

// Health returns a handler reporting service liveness as JSON, including the
// service name and build version.
func Health(service, version string) http.HandlerFunc {
	body, _ := json.Marshal(map[string]string{
		"status":  "ok",
		"service": service,
		"version": version,
	})

	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
