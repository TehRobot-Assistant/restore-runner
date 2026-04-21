// Package web serves RestoreRunner's HTTP UI.
//
// Routes:
//   GET  /health          — unauth, container healthcheck
//   GET  /setup           — first-run admin wizard (when no users exist)
//   POST /setup           — creates the admin + auto-logs-in
//   GET  /login           — login form
//   POST /login           — issues session cookie
//   POST /logout          — clears session
//   GET  /                — dashboard: drop-zone + past runs list
//   POST /upload          — multipart archive upload entrypoint
//   GET  /picker/{id}     — template picker when archive had >1 XML
//   POST /picker/{id}     — user's chosen XML; triggers the docker run
//   GET  /run/{id}        — single-run detail page (status + live logs)
//   GET  /run/{id}/logs   — SSE stream of live + persisted logs
//   GET  /run/{id}/preview/* — reverse-proxied sandbox WebUI (v0.4)
//   POST /run/{id}/stop   — stops + removes the container
//   POST /run/{id}/relaunch — re-runs the already-extracted archive
//   POST /run/{id}/delete — removes the run (container first if running)
package web

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/trstudios/restore-runner/internal/auth"
	"github.com/trstudios/restore-runner/internal/previewproxy"
	"github.com/trstudios/restore-runner/internal/sandbox"
	"github.com/trstudios/restore-runner/internal/upload"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server holds every dependency the handlers need.
type Server struct {
	DB             *sql.DB
	Logger         *slog.Logger
	Sandbox        *sandbox.Client
	Orch           *upload.Orchestrator
	Proxies        *previewproxy.Registry
	RunTimeout     time.Duration // auto-stop after this long
	MemoryBytes    int64
	CPUs           float64
	MaxUploadBytes int64
	HostDeny       []string // extra host path prefixes the sandbox must never touch

	tpl *template.Template
}

// NewServer wires templates + helpers.
func NewServer(
	db *sql.DB, logger *slog.Logger,
	sb *sandbox.Client, orch *upload.Orchestrator,
	proxies *previewproxy.Registry,
	runTimeout time.Duration, memBytes int64, cpus float64, maxUpload int64,
	hostDeny []string,
) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	tplFS, err := fs.Sub(assets, "templates")
	if err != nil {
		return nil, err
	}
	var tpl *template.Template
	renderBody := func(name string, data any) (template.HTML, error) {
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, name, data); err != nil {
			return "", err
		}
		return template.HTML(buf.String()), nil
	}
	tpl = template.New("").Funcs(template.FuncMap{
		"fmtTime":    fmtTime,
		"agoT":       agoT,
		"fmtSize":    fmtSize,
		"renderBody": renderBody,
	})
	tpl, err = tpl.ParseFS(tplFS, "*.html")
	if err != nil {
		return nil, err
	}
	if proxies == nil {
		proxies = previewproxy.NewRegistry()
	}
	return &Server{
		DB: db, Logger: logger, Sandbox: sb, Orch: orch,
		Proxies:        proxies,
		RunTimeout:     runTimeout,
		MemoryBytes:    memBytes,
		CPUs:           cpus,
		MaxUploadBytes: maxUpload,
		HostDeny:       hostDeny,
		tpl:            tpl,
	}, nil
}

// Handler returns the fully-configured http.Handler (mux + middleware).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /setup", s.handleSetupGet)
	mux.HandleFunc("POST /setup", s.handleSetupPost)
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("GET /health", s.handleHealth)

	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("POST /upload", s.handleUpload)
	mux.HandleFunc("GET /picker/{id}", s.handlePickerGet)
	mux.HandleFunc("POST /picker/{id}", s.handlePickerPost)
	mux.HandleFunc("GET /run/{id}", s.handleRunDetail)
	mux.HandleFunc("GET /run/{id}/logs", s.handleRunLogs)
	// Preview proxy: any method, any sub-path. Go 1.22 ServeMux uses
	// {rest...} to capture the remaining path segments as a single
	// wildcard. We don't read r.PathValue("rest") — the proxy's
	// Director rewrites the URL based on the raw r.URL.Path.
	mux.HandleFunc("/run/{id}/preview", s.handleRunPreview)
	mux.HandleFunc("/run/{id}/preview/{rest...}", s.handleRunPreview)
	mux.HandleFunc("POST /run/{id}/stop", s.handleRunStop)
	mux.HandleFunc("POST /run/{id}/relaunch", s.handleRunRelaunch)
	mux.HandleFunc("POST /run/{id}/delete", s.handleRunDelete)
	mux.HandleFunc("POST /logout", s.handleLogout)

	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	return auth.Middleware(s.DB, mux)
}

// Listen returns a listener bound to 0.0.0.0:port.
func (s *Server) Listen(port int) (net.Listener, error) {
	return net.Listen("tcp", ":"+strconv.Itoa(port))
}

// --- template helpers -----------------------------------------------------

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04")
}

func agoT(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	default:
		return strconv.Itoa(int(d.Hours())/24) + "d ago"
	}
}

func fmtSize(n int64) string {
	const k = 1024
	if n < k {
		return strconv.FormatInt(n, 10) + " B"
	}
	if n < k*k {
		return strconv.FormatFloat(float64(n)/k, 'f', 1, 64) + " KiB"
	}
	if n < k*k*k {
		return strconv.FormatFloat(float64(n)/(k*k), 'f', 1, 64) + " MiB"
	}
	return strconv.FormatFloat(float64(n)/(k*k*k), 'f', 2, 64) + " GiB"
}

// Used by package-internal callers that need the background ctx that
// survives the request lifetime (e.g. long docker runs triggered by a
// form submit).
func detachedContext() context.Context { return context.Background() }
