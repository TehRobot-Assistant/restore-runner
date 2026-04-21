// restorerunner binary. Serves the web UI + runs the rehearsal scheduler.
//
// v0.1 shape:
//
//	restorerunner serve        start the server (default)
//	restorerunner version      print build info
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/trstudios/restore-runner/internal/db"
	"github.com/trstudios/restore-runner/internal/notify"
	"github.com/trstudios/restore-runner/internal/scheduler"
	"github.com/trstudios/restore-runner/internal/web"
)

var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) >= 2 {
		switch args[1] {
		case "version":
			fmt.Printf("restorerunner %s (commit=%s, built=%s)\n", version, commit, buildTime)
			return nil
		case "serve", "":
			// fallthrough
		default:
			return fmt.Errorf("unknown command %q (use: serve, version)", args[1])
		}
	}

	cfgDir := envOr("RR_CONFIG_DIR", "/config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", cfgDir, err)
	}
	dbPath := filepath.Join(cfgDir, "restorerunner.db")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	port := intEnv("RR_PORT", 8920)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configured apprise URLs for the notifier. Fresh on every load so
	// settings changes take effect on next scheduler sweep (no restart).
	var appriseURLs []string
	_ = db.SettingGetJSON(ctx, database, db.KeyAppriseURLs, &appriseURLs)
	notifier := notify.New(appriseURLs, logger)

	sch := &scheduler.Scheduler{DB: database, Logger: logger, Notifier: notifier}
	go sch.Run(ctx)

	server, err := web.NewServer(database, logger, sch)
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}
	listener, err := server.Listen(port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	logger.Info("restorerunner starting",
		"version", version, "commit", commit, "port", port,
		"config", cfgDir, "db", dbPath)

	srv := &http.Server{
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(listener) }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case sig := <-sigCh:
		logger.Info("shutdown signal", "sig", sig.String())
		shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
		cancel()
	}
	return nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func intEnv(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}
