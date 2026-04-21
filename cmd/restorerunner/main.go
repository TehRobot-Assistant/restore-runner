// Command restorerunner — upload an Unraid AppData backup archive, boot
// the captured container in a sandbox, watch its logs, one click to stop.
//
// Runtime contract (matches every TR Studios app):
//   - Single data directory at /config.
//   - No YAML config. Tunables via env vars; admin via web wizard.
//   - Binds 0.0.0.0:8922 inside the container; host-port mapping gates
//     external exposure.
//   - Needs /var/run/docker.sock mounted to do its job — refuses to
//     start containers otherwise (with a friendly error).
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/trstudios/restore-runner/internal/auth"
	"github.com/trstudios/restore-runner/internal/db"
	"github.com/trstudios/restore-runner/internal/previewproxy"
	"github.com/trstudios/restore-runner/internal/sandbox"
	"github.com/trstudios/restore-runner/internal/upload"
	"github.com/trstudios/restore-runner/internal/web"
)

// Build-time metadata, overridable via -ldflags.
var (
	version   = "0.4"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	configPath := envOr("CONFIG_PATH", "/config")
	port, _ := strconv.Atoi(envOr("PORT", "8922"))
	if port == 0 {
		port = 8922
	}
	dockerSocket := envOr("DOCKER_HOST", "/var/run/docker.sock")
	dockerSocket = stripUnixScheme(dockerSocket)

	envAdminUser := envOr("ADMIN_USERNAME", "admin")
	envAdminPass := os.Getenv("ADMIN_PASSWORD")

	// RR_MAX_UPLOAD_MB caps the archive size in MiB.
	maxMB, _ := strconv.Atoi(envOr("RR_MAX_UPLOAD_MB", "2048"))
	if maxMB <= 0 {
		maxMB = 2048
	}
	maxBytes := int64(maxMB) * 1024 * 1024

	// RR_RUN_TIMEOUT_MIN auto-stops containers after N minutes.
	timeoutMin, _ := strconv.Atoi(envOr("RR_RUN_TIMEOUT_MIN", "10"))
	if timeoutMin <= 0 {
		timeoutMin = 10
	}
	runTimeout := time.Duration(timeoutMin) * time.Minute

	// Resource caps for sandboxed containers.
	memoryBytes := int64(1 << 30) // 1 GiB
	cpus := 1.0

	if err := os.MkdirAll(configPath, 0o755); err != nil {
		logger.Error("make config dir", "path", configPath, "err", err)
		os.Exit(1)
	}
	uploadsDir := filepath.Join(configPath, "uploads")
	if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
		logger.Error("make uploads dir", "path", uploadsDir, "err", err)
		os.Exit(1)
	}

	dbPath := filepath.Join(configPath, "restorerunner.db")
	database, err := db.Open(dbPath)
	if err != nil {
		logger.Error("open database", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer database.Close()

	ctx := context.Background()
	if err := auth.BootstrapAdminFromEnv(ctx, database, envAdminUser, envAdminPass); err != nil {
		logger.Error("bootstrap admin", "err", err)
		os.Exit(1)
	}
	if adminExists, _ := auth.AdminExists(ctx, database); adminExists {
		if envAdminPass != "" {
			logger.Info("admin seeded from ADMIN_PASSWORD env", "username", envAdminUser)
		} else {
			logger.Info("admin already configured")
		}
	} else {
		logger.Info("no admin yet — browse to the UI to create one via /setup")
	}

	// Docker client. We don't fail the whole app if the socket is
	// missing at startup — the health endpoint still works so Docker's
	// own healthcheck passes, and the UI surfaces a friendly error
	// when the user tries to start a container.
	sb, err := sandbox.NewClient(dockerSocket)
	if err != nil {
		logger.Error("docker client init", "err", err)
		os.Exit(1)
	}
	defer sb.Close()

	pingCtx, pingCancel := context.WithTimeout(ctx, 3*time.Second)
	if err := sb.Ping(pingCtx); err != nil {
		logger.Warn("docker socket unreachable at startup — check that /var/run/docker.sock is mounted",
			"socket", dockerSocket, "err", err)
	}
	pingCancel()

	// --- Sandbox network bring-up (v0.4) ------------------------------
	// Create the isolated --internal network (idempotent), and connect
	// ourselves to it so the reverse proxy can reach sandbox IPs. Self-
	// detection uses os.Hostname() which docker sets to the short
	// container ID by default. A tolerant warning is logged if either
	// step fails — the app still boots; the user will see a clear error
	// when they try to start a sandbox if docker is truly unreachable.
	netCtx, netCancel := context.WithTimeout(ctx, 10*time.Second)
	if err := sb.EnsureSandboxNetwork(netCtx); err != nil {
		logger.Warn("ensure sandbox net — sandboxes will fail to start until docker is reachable",
			"err", err)
	} else {
		host, herr := os.Hostname()
		if herr != nil || host == "" {
			logger.Warn("cannot detect own container id — reverse proxy may not reach sandbox by IP", "err", herr)
		} else if err := sb.ConnectSelf(netCtx, host); err != nil {
			logger.Warn("connect self to sandbox net — preview may be unreachable on hardened docker setups", "err", err)
		}
	}
	netCancel()

	// Optional extra host denylist — path prefixes that the sandbox
	// must never bind-mount, in addition to the built-in /mnt/user,
	// /boot, /etc, etc. Comma-separated.
	var hostDeny []string
	if v := os.Getenv("RR_HOST_DENY_PREFIXES"); v != "" {
		for _, p := range strings.Split(v, ",") {
			if t := strings.TrimSpace(p); t != "" {
				hostDeny = append(hostDeny, t)
			}
		}
	}

	orch := &upload.Orchestrator{
		DB:       database,
		BaseDir:  uploadsDir,
		MaxBytes: maxBytes,
	}

	// --- Orphan sweep on startup ---------------------------------------
	// A previous crash or restart may have left rr-* containers behind,
	// or runs marked "running" with no matching container. Reconcile.
	sweepCtx, sweepCancel := context.WithTimeout(ctx, 15*time.Second)
	// Keep IDs is intentionally empty — we're restarting fresh; any
	// container labeled with com.trstudios.restorerunner from a previous
	// session is orphan.
	if removed, err := sb.SweepOrphans(sweepCtx, map[string]bool{}); err != nil {
		logger.Warn("orphan sweep", "err", err)
	} else if len(removed) > 0 {
		logger.Info("orphan containers swept", "names", removed)
	}
	// Flip any "running" DB rows to "stopped" since no corresponding
	// container exists anymore.
	runningIDs, _ := db.ListRunningRunIDs(sweepCtx, database)
	for _, id := range runningIDs {
		_ = db.UpdateRunStopped(sweepCtx, database, id)
	}
	sweepCancel()

	proxies := previewproxy.NewRegistry()
	srv, err := web.NewServer(database, logger, sb, orch, proxies,
		runTimeout, memoryBytes, cpus, maxBytes, hostDeny)
	if err != nil {
		logger.Error("init web server", "err", err)
		os.Exit(1)
	}
	listener, err := srv.Listen(port)
	if err != nil {
		logger.Error("bind port", "port", port, "err", err)
		os.Exit(1)
	}

	// Upload endpoint can take minutes for multi-GB archives → generous
	// write timeout. SSE log stream holds connections open → don't
	// aggressively idle-close.
	httpSrv := &http.Server{
		Handler:      srv.Handler(),
		ReadTimeout:  0, // uploads can be slow; rely on MaxBytesReader + context
		WriteTimeout: 0, // SSE streams; finite per-handler timers instead
		IdleTimeout:  120 * time.Second,
	}

	logger.Info("restorerunner starting",
		"version", version, "commit", commit, "buildTime", buildTime,
		"port", port, "config", configPath, "db", dbPath,
		"dockerSocket", dockerSocket,
		"maxUploadMB", maxMB, "runTimeoutMin", timeoutMin)

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(listener) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("http server", "err", err)
			os.Exit(1)
		}
	case s := <-sig:
		logger.Info("shutdown signal", "signal", s)
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func stripUnixScheme(s string) string {
	const p = "unix://"
	if len(s) > len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}
