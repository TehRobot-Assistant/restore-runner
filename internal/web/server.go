// Package web serves RestoreRunner's HTTP UI. Flows:
//
//  1. First-run /setup wizard — collects admin username + password.
//  2. /login — session cookie issuer.
//  3. Everything else — dashboard, repo detail, add-repo wizard, settings.
//     Gated by the auth middleware.
//
// All configuration lives in SQLite settings + repos tables; no YAML.
package web

import (
	"bytes"
	"database/sql"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/trstudios/restore-runner/internal/auth"
	"github.com/trstudios/restore-runner/internal/scheduler"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server holds dependencies for every handler.
type Server struct {
	DB        *sql.DB
	Logger    *slog.Logger
	Scheduler *scheduler.Scheduler

	tpl *template.Template
}

// NewServer wires templates.
func NewServer(db *sql.DB, logger *slog.Logger, sch *scheduler.Scheduler) (*Server, error) {
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
		"upper":      upper,
		"humanBytes": humanBytes,
		"renderBody": renderBody,
	})
	tpl, err = tpl.ParseFS(tplFS, "*.html")
	if err != nil {
		return nil, err
	}
	return &Server{DB: db, Logger: logger, Scheduler: sch, tpl: tpl}, nil
}

// Handler returns the mux with auth middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public.
	mux.HandleFunc("GET /setup", s.handleSetupGet)
	mux.HandleFunc("POST /setup", s.handleSetupPost)
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("GET /health", s.handleHealth)

	// Authenticated.
	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /repos/new", s.handleRepoNewGet)
	mux.HandleFunc("POST /repos/new", s.handleRepoNewPost)
	mux.HandleFunc("GET /repo/{id}", s.handleRepoDetail)
	mux.HandleFunc("POST /repo/{id}/rehearse", s.handleRepoRehearse)
	mux.HandleFunc("POST /repo/{id}/recapture", s.handleRepoRecapture)
	mux.HandleFunc("POST /repo/{id}/toggle", s.handleRepoToggle)
	mux.HandleFunc("POST /repo/{id}/delete", s.handleRepoDelete)
	mux.HandleFunc("GET /repo/{id}/rehearsals.csv", s.handleRepoRehearsalExport)
	mux.HandleFunc("GET /export/rehearsals.csv", s.handleFleetRehearsalExport)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /settings", s.handleSettingsGet)
	mux.HandleFunc("POST /settings", s.handleSettingsPost)

	// Static assets.
	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	return auth.Middleware(s.DB, mux)
}

// Listen binds 0.0.0.0:port.
func (s *Server) Listen(port int) (net.Listener, error) {
	return net.Listen("tcp", ":"+itoa(port))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
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
		return itoa(int(d.Minutes())) + "m ago"
	case d < 48*time.Hour:
		return itoa(int(d.Hours())) + "h ago"
	default:
		return itoa(int(d.Hours())/24) + "d ago"
	}
}

func upper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}

// humanBytes formats a size like 1.2GB / 850KB.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return itoa(int(n)) + "B"
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	val := float64(n) / float64(div)
	// one-decimal formatter without fmt.Sprintf dep creep
	suffix := "KMGTPE"[exp]
	whole := int(val)
	tenths := int((val - float64(whole)) * 10)
	if tenths == 0 {
		return itoa(whole) + string(suffix) + "B"
	}
	return itoa(whole) + "." + itoa(tenths) + string(suffix) + "B"
}
