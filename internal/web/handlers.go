package web

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/trstudios/restore-runner/internal/auth"
	"github.com/trstudios/restore-runner/internal/baseline"
	"github.com/trstudios/restore-runner/internal/db"
	"github.com/trstudios/restore-runner/internal/restic"
)

// --- /setup (first-run admin bootstrap) -----------------------------------

func (s *Server) handleSetupGet(w http.ResponseWriter, r *http.Request) {
	exists, err := auth.AdminExists(r.Context(), s.DB)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderPage(w, "Welcome to RestoreRunner", "setup-content", map[string]any{})
}

func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	exists, _ := auth.AdminExists(ctx, s.DB)
	if exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	errMsg := ""
	switch {
	case username == "":
		errMsg = "Username required."
	case len(password) < 8:
		errMsg = "Password must be at least 8 characters."
	case password != confirm:
		errMsg = "Passwords don't match."
	}
	if errMsg != "" {
		s.renderPage(w, "Welcome to RestoreRunner", "setup-content", map[string]any{
			"Error":    errMsg,
			"Username": username,
		})
		return
	}
	u, err := auth.CreateAdmin(ctx, s.DB, username, password)
	if err != nil {
		s.renderPage(w, "Welcome to RestoreRunner", "setup-content", map[string]any{
			"Error":    "Could not create admin: " + err.Error(),
			"Username": username,
		})
		return
	}
	// Master key gets generated on first use; preseed here so the /repos/new
	// flow doesn't have to handle a first-time race.
	if _, err := db.EnsureMasterKey(ctx, s.DB); err != nil {
		s.Logger.Warn("ensure master key at setup", "err", err)
	}
	if token, err := auth.CreateSession(ctx, s.DB, u.ID); err == nil {
		auth.SetSessionCookie(w, token)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- /login + /logout -----------------------------------------------------

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if u := auth.UserFromContext(r.Context()); u != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderPage(w, "Log in — RestoreRunner", "login-content", map[string]any{})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	u, err := auth.Authenticate(ctx, s.DB, username, password)
	if err != nil || u == nil {
		s.renderPage(w, "Log in — RestoreRunner", "login-content", map[string]any{
			"Error":    "Invalid username or password.",
			"Username": username,
		})
		return
	}
	if token, err := auth.CreateSession(ctx, s.DB, u.ID); err == nil {
		auth.SetSessionCookie(w, token)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Pull the current session token from the cookie and delete it.
	if c, err := r.Cookie(auth.SessionCookieName); err == nil {
		_ = auth.DeleteSession(r.Context(), s.DB, c.Value)
	}
	auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- /health --------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"ts":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
}

// --- / (dashboard) --------------------------------------------------------

type dashboardRow struct {
	ID              int64
	Name            string
	Kind            string
	RepoURL         string
	SourcePath      string
	Enabled         bool
	CadenceHours    int
	SampleSize      int
	LastRehearsedAt time.Time
	LastStatus      string // '' | 'pass' | 'degraded' | 'fail'
	NextDueAt       time.Time
	BaselineFiles   int64
	BaselineBytes   int64
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	rows, err := s.DB.QueryContext(r.Context(), `
		SELECT r.id, r.name, r.kind, r.repo_url, r.source_path, r.enabled,
		       r.cadence_hours, r.sample_size,
		       r.last_rehearsed_at, COALESCE(r.last_status, ''),
		       COALESCE(b.file_count, 0), COALESCE(b.total_bytes, 0)
		FROM repos r
		LEFT JOIN baselines b ON b.repo_id = r.id
		ORDER BY r.name
	`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []dashboardRow
	for rows.Next() {
		var row dashboardRow
		var enabled int
		var lastUnix int64
		if err := rows.Scan(&row.ID, &row.Name, &row.Kind, &row.RepoURL, &row.SourcePath,
			&enabled, &row.CadenceHours, &row.SampleSize,
			&lastUnix, &row.LastStatus,
			&row.BaselineFiles, &row.BaselineBytes); err != nil {
			continue
		}
		row.Enabled = enabled == 1
		if lastUnix > 0 {
			row.LastRehearsedAt = time.Unix(lastUnix, 0)
			row.NextDueAt = row.LastRehearsedAt.Add(time.Duration(row.CadenceHours) * time.Hour)
		}
		list = append(list, row)
	}

	// "Last rehearsal" across all repos for the header timer.
	var lastUnix int64
	_ = s.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(MAX(finished_at), 0) FROM rehearsals`).Scan(&lastUnix)
	var lastRehearsal time.Time
	if lastUnix > 0 {
		lastRehearsal = time.Unix(lastUnix, 0)
	}

	firstRun := len(list) == 0

	s.renderPage(w, "RestoreRunner — Dashboard", "dashboard-content", map[string]any{
		"User":              user,
		"Repos":             list,
		"FirstRun":          firstRun,
		"LastRehearsal":     lastRehearsal,
		"LastRehearsalUnix": lastUnix,
		"FlashAdded":        r.URL.Query().Get("added") == "1",
		"FlashRehearsing":   r.URL.Query().Get("rehearsing") == "1",
	})
}

// --- /repos/new (add-repo wizard) -----------------------------------------

func (s *Server) handleRepoNewGet(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	defaultCadence := db.SettingGetInt(r.Context(), s.DB, db.KeyDefaultCadenceHours, 168)
	defaultSample := db.SettingGetInt(r.Context(), s.DB, db.KeyDefaultSampleSize, 30)
	s.renderPage(w, "New backup repo — RestoreRunner", "repo-new-content", map[string]any{
		"User":           user,
		"DefaultCadence": defaultCadence,
		"DefaultSample":  defaultSample,
	})
}

func (s *Server) handleRepoNewPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	_ = r.ParseForm()

	form := map[string]string{
		"name":        strings.TrimSpace(r.FormValue("name")),
		"kind":        strings.TrimSpace(r.FormValue("kind")),
		"repo_url":    strings.TrimSpace(r.FormValue("repo_url")),
		"password":    r.FormValue("password"),
		"source_path": strings.TrimSpace(r.FormValue("source_path")),
		"cadence":     strings.TrimSpace(r.FormValue("cadence_hours")),
		"sample":      strings.TrimSpace(r.FormValue("sample_size")),
		"exclude":     r.FormValue("exclude_globs"),
		"capture_now": r.FormValue("capture_now"),
	}

	errMsg := validateRepoForm(form)
	if errMsg == "" {
		// Probe the repo before we store anything. Fail early on bad creds.
		adapter, err := restic.NewAdapter(form["repo_url"], form["password"])
		if err != nil {
			errMsg = "Restic binary missing in container: " + err.Error()
		} else if err := adapter.CheckAccess(ctx); err != nil {
			errMsg = "Could not open restic repo — check URL and password: " + err.Error()
		}
	}
	if errMsg != "" {
		s.renderPage(w, "New backup repo — RestoreRunner", "repo-new-content", map[string]any{
			"User":  user,
			"Error": errMsg,
			"Form":  form,
		})
		return
	}

	// Encrypt password at rest.
	mk, err := db.EnsureMasterKey(ctx, s.DB)
	if err != nil {
		http.Error(w, "master key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pwEnc, err := db.Encrypt(mk, []byte(form["password"]))
	if err != nil {
		http.Error(w, "encrypt: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cadence := atoiOr(form["cadence"], 168)
	sample := atoiOr(form["sample"], 30)
	if cadence < 1 {
		cadence = 1
	}
	if sample < 1 {
		sample = 1
	}

	var newID int64
	row := s.DB.QueryRowContext(ctx, `
		INSERT INTO repos (name, kind, repo_url, password_enc, source_path,
		                   sample_size, cadence_hours, exclude_globs,
		                   enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
		RETURNING id
	`, form["name"], form["kind"], form["repo_url"], pwEnc, form["source_path"],
		sample, cadence, form["exclude"], time.Now().Unix())
	if err := row.Scan(&newID); err != nil {
		http.Error(w, "insert repo: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Audit.
	var uid int64
	if user != nil {
		uid = user.ID
	}
	_, _ = s.DB.ExecContext(ctx, `
		INSERT INTO actions (repo_id, user_id, action, detail, created_at)
		VALUES (?, ?, 'enroll', ?, ?)
	`, newID, uid, form["name"]+" enrolled", time.Now().Unix())

	// Baseline capture — can be long for large sources, fire in a goroutine.
	if form["capture_now"] == "on" {
		go func(id int64) {
			bgCtx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
			defer cancel()
			excludes := strings.Split(form["exclude"], "\n")
			if err := baseline.Capture(bgCtx, s.DB, id, form["source_path"], excludes, nil); err != nil {
				s.Logger.Warn("baseline capture", "repo_id", id, "err", err)
			}
		}(newID)
	}

	http.Redirect(w, r, "/?added=1", http.StatusSeeOther)
}

func validateRepoForm(form map[string]string) string {
	if form["name"] == "" {
		return "Name required."
	}
	if form["kind"] != "restic" {
		return "Kind must be 'restic' in v0.1 (Borg and Kopia coming soon)."
	}
	if form["repo_url"] == "" {
		return "Repo URL required."
	}
	if form["password"] == "" {
		return "Password required — paste the restic repo password (we'll store it encrypted)."
	}
	if form["source_path"] == "" {
		return "Source path required — the live directory to compare the backup against."
	}
	if !strings.HasPrefix(form["source_path"], "/") {
		return "Source path must be absolute (start with /)."
	}
	// Reject pseudo-filesystems + dangerous roots. Walking these takes
	// hours, spams kernel logs, and produces a baseline that's useless.
	for _, bad := range []string{"/proc", "/sys", "/dev", "/run"} {
		if form["source_path"] == bad || strings.HasPrefix(form["source_path"], bad+"/") {
			return "Source path cannot be under " + bad + " — that's a kernel pseudo-filesystem, not a real directory."
		}
	}
	if form["source_path"] == "/" {
		return "Source path cannot be the container root. Mount the real data directory (e.g. /srv/data) and point here."
	}
	return ""
}

// --- /repo/{id} (detail) --------------------------------------------------

type repoDetail struct {
	ID               int64
	Name             string
	Kind             string
	RepoURL          string
	SourcePath       string
	Enabled          bool
	CadenceHours     int
	SampleSize       int
	ExcludeGlobs     string
	LastRehearsedAt  time.Time
	LastStatus       string
	BaselineCaptured time.Time
	BaselineFiles    int64
	BaselineBytes    int64
	BaselineHashable int64
	Rehearsals       []rehearsalRow
}

type rehearsalRow struct {
	ID             int64
	StartedAt      time.Time
	FinishedAt     time.Time
	Status         string
	SampledCount   int
	MatchedCount   int
	DivergedCount  int
	MissingCount   int
	LiveFileCount  int64
	LiveTotalBytes int64
	StructuralOK   bool
	Detail         string
	TriggeredBy    string
}

func (s *Server) handleRepoDetail(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	idStr := r.PathValue("id")
	id := atoiOr(idStr, 0)
	if id == 0 {
		http.NotFound(w, r)
		return
	}

	d := repoDetail{ID: int64(id)}
	var enabled int
	var lastRehearsed int64
	err := s.DB.QueryRowContext(r.Context(), `
		SELECT name, kind, repo_url, source_path, enabled, cadence_hours, sample_size,
		       COALESCE(exclude_globs, ''), last_rehearsed_at, COALESCE(last_status, '')
		FROM repos WHERE id = ?
	`, id).Scan(&d.Name, &d.Kind, &d.RepoURL, &d.SourcePath, &enabled, &d.CadenceHours, &d.SampleSize,
		&d.ExcludeGlobs, &lastRehearsed, &d.LastStatus)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	d.Enabled = enabled == 1
	if lastRehearsed > 0 {
		d.LastRehearsedAt = time.Unix(lastRehearsed, 0)
	}

	// Baseline metadata (may be absent — empty row).
	var capturedUnix int64
	_ = s.DB.QueryRowContext(r.Context(), `
		SELECT captured_at, file_count, total_bytes, hashable_count
		FROM baselines WHERE repo_id = ?
	`, id).Scan(&capturedUnix, &d.BaselineFiles, &d.BaselineBytes, &d.BaselineHashable)
	if capturedUnix > 0 {
		d.BaselineCaptured = time.Unix(capturedUnix, 0)
	}

	// Last 20 rehearsals.
	rhRows, err := s.DB.QueryContext(r.Context(), `
		SELECT id, started_at, finished_at, status,
		       sampled_count, matched_count, diverged_count, missing_count,
		       live_file_count, live_total_bytes, structural_ok,
		       detail, COALESCE(triggered_by, '')
		FROM rehearsals WHERE repo_id = ?
		ORDER BY started_at DESC LIMIT 20
	`, id)
	if err == nil {
		defer rhRows.Close()
		for rhRows.Next() {
			var rh rehearsalRow
			var startedUnix, finishedUnix int64
			var structOK int
			if err := rhRows.Scan(&rh.ID, &startedUnix, &finishedUnix, &rh.Status,
				&rh.SampledCount, &rh.MatchedCount, &rh.DivergedCount, &rh.MissingCount,
				&rh.LiveFileCount, &rh.LiveTotalBytes, &structOK,
				&rh.Detail, &rh.TriggeredBy); err == nil {
				rh.StartedAt = time.Unix(startedUnix, 0)
				if finishedUnix > 0 {
					rh.FinishedAt = time.Unix(finishedUnix, 0)
				}
				rh.StructuralOK = structOK == 1
				d.Rehearsals = append(d.Rehearsals, rh)
			}
		}
	}

	s.renderPage(w, d.Name+" — RestoreRunner", "repo-detail-content", map[string]any{
		"User":     user,
		"Repo":     d,
		"FlashRun": r.URL.Query().Get("ran") == "1",
		"FlashCap": r.URL.Query().Get("capturing") == "1",
	})
}

// --- /repo/{id}/rehearse (Run now) ----------------------------------------

func (s *Server) handleRepoRehearse(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id := int64(atoiOr(idStr, 0))
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	// Verify exists.
	var dummy int
	err := s.DB.QueryRowContext(r.Context(), `SELECT 1 FROM repos WHERE id=?`, id).Scan(&dummy)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if s.Scheduler != nil {
		s.Scheduler.TriggerRepo(id)
	}
	http.Redirect(w, r, "/repo/"+idStr+"?ran=1", http.StatusSeeOther)
}

// --- /repo/{id}/recapture -------------------------------------------------

func (s *Server) handleRepoRecapture(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id := int64(atoiOr(idStr, 0))
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	var sourcePath, excludes string
	err := s.DB.QueryRowContext(ctx, `
		SELECT source_path, COALESCE(exclude_globs, '') FROM repos WHERE id=?
	`, id).Scan(&sourcePath, &excludes)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	// Baseline capture can take hours; background it.
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
		defer cancel()
		list := strings.Split(excludes, "\n")
		if err := baseline.Capture(bgCtx, s.DB, id, sourcePath, list, nil); err != nil {
			s.Logger.Warn("recapture baseline", "repo_id", id, "err", err)
		}
	}()
	http.Redirect(w, r, "/repo/"+idStr+"?capturing=1", http.StatusSeeOther)
}

// --- /repo/{id}/toggle (enable/disable) -----------------------------------

func (s *Server) handleRepoToggle(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id := int64(atoiOr(idStr, 0))
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	_, err := s.DB.ExecContext(r.Context(),
		`UPDATE repos SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?`, id)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/repo/"+idStr, http.StatusSeeOther)
}

// --- /repo/{id}/delete ----------------------------------------------------

func (s *Server) handleRepoDelete(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id := int64(atoiOr(idStr, 0))
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	// Confirmation: user must re-type the repo name.
	confirm := strings.TrimSpace(r.FormValue("confirm_name"))
	var name string
	err := s.DB.QueryRowContext(r.Context(), `SELECT name FROM repos WHERE id=?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if confirm != name {
		http.Error(w, "confirm name does not match — refusing delete", http.StatusBadRequest)
		return
	}
	if _, err := s.DB.ExecContext(r.Context(), `DELETE FROM repos WHERE id=?`, id); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- /settings ------------------------------------------------------------

type settingsForm struct {
	DefaultCadenceHours int
	DefaultSampleSize   int
	AppriseURLs         []string
	NotifyOnFail        bool
	NotifyOnDegraded    bool
	NotifyOnPass        bool
	ScratchDir          string
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	form := s.loadSettings(r.Context())
	s.renderPage(w, "Settings — RestoreRunner", "settings-content", map[string]any{
		"User":     user,
		"Settings": form,
		"Saved":    r.URL.Query().Get("saved") == "1",
	})
}

func (s *Server) handleSettingsPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()

	_ = db.SettingSet(ctx, s.DB, db.KeyDefaultCadenceHours, strings.TrimSpace(r.FormValue("default_cadence_hours")))
	_ = db.SettingSet(ctx, s.DB, db.KeyDefaultSampleSize, strings.TrimSpace(r.FormValue("default_sample_size")))
	_ = db.SettingSet(ctx, s.DB, db.KeyScratchDir, strings.TrimSpace(r.FormValue("scratch_dir")))
	_ = db.SettingSet(ctx, s.DB, db.KeyNotifyOnFail, boolForm(r.FormValue("notify_on_fail")))
	_ = db.SettingSet(ctx, s.DB, db.KeyNotifyOnDegraded, boolForm(r.FormValue("notify_on_degraded")))
	_ = db.SettingSet(ctx, s.DB, db.KeyNotifyOnPass, boolForm(r.FormValue("notify_on_pass")))

	urls := splitLines(r.FormValue("apprise_urls"))
	_ = db.SettingSetJSON(ctx, s.DB, db.KeyAppriseURLs, urls)

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) loadSettings(ctx context.Context) settingsForm {
	var form settingsForm
	form.DefaultCadenceHours = db.SettingGetInt(ctx, s.DB, db.KeyDefaultCadenceHours, 168)
	form.DefaultSampleSize = db.SettingGetInt(ctx, s.DB, db.KeyDefaultSampleSize, 30)
	form.NotifyOnFail = db.SettingGetBool(ctx, s.DB, db.KeyNotifyOnFail, true)
	form.NotifyOnDegraded = db.SettingGetBool(ctx, s.DB, db.KeyNotifyOnDegraded, true)
	form.NotifyOnPass = db.SettingGetBool(ctx, s.DB, db.KeyNotifyOnPass, false)
	form.ScratchDir, _ = db.SettingGet(ctx, s.DB, db.KeyScratchDir)
	_ = db.SettingGetJSON(ctx, s.DB, db.KeyAppriseURLs, &form.AppriseURLs)
	return form
}

// --- CSV exports ----------------------------------------------------------

var rehearsalCSVColumns = []string{
	"repo_name", "repo_kind", "repo_url", "source_path",
	"started_at", "finished_at", "status",
	"sampled_count", "matched_count", "diverged_count", "missing_count",
	"live_file_count", "live_total_bytes", "structural_ok",
	"detail", "triggered_by",
}

func (s *Server) handleFleetRehearsalExport(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.QueryContext(r.Context(), `
		SELECT r.name, r.kind, r.repo_url, r.source_path,
		       rh.started_at, rh.finished_at, rh.status,
		       rh.sampled_count, rh.matched_count, rh.diverged_count, rh.missing_count,
		       rh.live_file_count, rh.live_total_bytes, rh.structural_ok,
		       rh.detail, COALESCE(rh.triggered_by, '')
		FROM rehearsals rh JOIN repos r ON r.id = rh.repo_id
		ORDER BY r.name, rh.started_at DESC`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	s.writeRehearsalCSV(w, "fleet.restore-runner-export."+time.Now().Format("2006-01-02")+".csv", rows)
}

func (s *Server) handleRepoRehearsalExport(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiOr(r.PathValue("id"), 0))
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	var name string
	err := s.DB.QueryRowContext(r.Context(), `SELECT name FROM repos WHERE id=?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), `
		SELECT r.name, r.kind, r.repo_url, r.source_path,
		       rh.started_at, rh.finished_at, rh.status,
		       rh.sampled_count, rh.matched_count, rh.diverged_count, rh.missing_count,
		       rh.live_file_count, rh.live_total_bytes, rh.structural_ok,
		       rh.detail, COALESCE(rh.triggered_by, '')
		FROM rehearsals rh JOIN repos r ON r.id = rh.repo_id
		WHERE rh.repo_id = ?
		ORDER BY rh.started_at DESC`, id)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	s.writeRehearsalCSV(w,
		sanitiseFilenamePart(name)+".restore-runner-export."+time.Now().Format("2006-01-02")+".csv",
		rows)
}

func (s *Server) writeRehearsalCSV(w http.ResponseWriter, filename string, rows *sql.Rows) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")

	cw := csv.NewWriter(w)
	_ = cw.Write(rehearsalCSVColumns)

	for rows.Next() {
		var (
			name, kind, repoURL, source, status, detail, triggeredBy string
			startedUnix, finishedUnix                                int64
			sampled, matched, diverged, missing                      int
			liveFiles, liveBytes                                     int64
			structOK                                                 int
		)
		if err := rows.Scan(&name, &kind, &repoURL, &source,
			&startedUnix, &finishedUnix, &status,
			&sampled, &matched, &diverged, &missing,
			&liveFiles, &liveBytes, &structOK,
			&detail, &triggeredBy); err != nil {
			continue
		}
		started := time.Unix(startedUnix, 0).UTC().Format(time.RFC3339)
		finished := ""
		if finishedUnix > 0 {
			finished = time.Unix(finishedUnix, 0).UTC().Format(time.RFC3339)
		}
		structStr := "true"
		if structOK == 0 {
			structStr = "false"
		}
		_ = cw.Write([]string{
			name, kind, repoURL, source,
			started, finished, status,
			itoa(sampled), itoa(matched), itoa(diverged), itoa(missing),
			itoa64(liveFiles), itoa64(liveBytes), structStr,
			detail, triggeredBy,
		})
		cw.Flush()
		if err := cw.Error(); err != nil {
			s.Logger.Warn("csv export write failed", "err", err)
			return
		}
	}
	cw.Flush()
}

// --- helpers --------------------------------------------------------------

// renderPage renders the named body template inside the layout shell.
func (s *Server) renderPage(w http.ResponseWriter, title, bodyTemplate string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = title
	data["Body"] = bodyTemplate
	// Preserve User if caller supplied it.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.Logger.Warn("render template", "tpl", bodyTemplate, "err", err)
	}
}

func atoiOr(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return fallback
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func itoa64(n int64) string {
	return itoa(int(n))
}

func boolForm(v string) string {
	switch v {
	case "on", "true", "1", "yes":
		return "true"
	}
	return "false"
}

func splitLines(s string) []string {
	out := []string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// sanitiseFilenamePart makes a string safe for Content-Disposition.
func sanitiseFilenamePart(s string) string {
	if s == "" {
		return "repo"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '.' || c == '-' || c == '_':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// keep the html/template import used (used by renderBody in server.go)
var _ = template.HTML("")
