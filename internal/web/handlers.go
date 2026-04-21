package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/trstudios/restore-runner/internal/auth"
	"github.com/trstudios/restore-runner/internal/db"
	"github.com/trstudios/restore-runner/internal/sandbox"
	"github.com/trstudios/restore-runner/internal/unraidxml"
	"github.com/trstudios/restore-runner/internal/upload"
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
	s.renderPage(w, "RestoreRunner — First-Run Setup", "setup-content",
		map[string]any{"Error": ""})
}

func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	exists, _ := auth.AdminExists(r.Context(), s.DB)
	if exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")
	if password != confirm {
		s.renderPage(w, "RestoreRunner — First-Run Setup", "setup-content",
			map[string]any{"Error": "Passwords don't match.", "Username": username})
		return
	}
	user, err := auth.CreateAdmin(r.Context(), s.DB, username, password)
	if err != nil {
		s.renderPage(w, "RestoreRunner — First-Run Setup", "setup-content",
			map[string]any{"Error": err.Error(), "Username": username})
		return
	}
	tok, err := auth.CreateSession(r.Context(), s.DB, user.ID)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, tok)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- /login + /logout -----------------------------------------------------

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(auth.SessionCookieName); err == nil {
		if user, err := auth.LookupSession(r.Context(), s.DB, cookie.Value); err == nil && user != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	s.renderPage(w, "Sign in — RestoreRunner", "login-content", map[string]any{"Error": ""})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	user, err := auth.Authenticate(r.Context(), s.DB, username, password)
	if err != nil {
		s.renderPage(w, "Sign in — RestoreRunner", "login-content",
			map[string]any{"Error": "Invalid username or password.", "Username": username})
		return
	}
	tok, err := auth.CreateSession(r.Context(), s.DB, user.ID)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, tok)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(auth.SessionCookieName); err == nil {
		_ = auth.DeleteSession(r.Context(), s.DB, cookie.Value)
	}
	auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- /health --------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.PingContext(r.Context()); err != nil {
		http.Error(w, "db down", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"ts":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
}

// --- / (dashboard) --------------------------------------------------------

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	runs, err := db.ListRuns(r.Context(), s.DB)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	// MaxUploadMiB in the UI helps the client-side drop-zone reject
	// oversize files before uploading.
	maxMiB := int64(0)
	if s.MaxUploadBytes > 0 {
		maxMiB = s.MaxUploadBytes / (1024 * 1024)
	}
	s.renderPage(w, "RestoreRunner", "dashboard-content", map[string]any{
		"User":       user,
		"Runs":       runs,
		"MaxUploadMiB": maxMiB,
		"Flash":      r.URL.Query().Get("flash"),
		"FlashErr":   r.URL.Query().Get("err"),
	})
}

// --- /upload --------------------------------------------------------------

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	// Enforce server-side cap even if the client sends a misleading
	// Content-Length. Orchestrator also caps per-part read.
	r.Body = http.MaxBytesReader(w, r.Body, s.MaxUploadBytes+1<<20) // +1MiB slack for multipart overhead

	res, err := s.Orch.Handle(r)
	if err != nil {
		if errors.Is(err, upload.ErrNoXML) {
			// The run row was already created + marked failed; surface a
			// friendly page that links to the run detail so the user can
			// delete it or see the error.
			http.Redirect(w, r, "/?err="+urlEncode("Archive didn't contain an Unraid container XML template. Nothing to boot."), http.StatusSeeOther)
			return
		}
		s.Logger.Warn("upload failed", "err", err)
		http.Redirect(w, r, "/?err="+urlEncode("Upload failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	// Route by template count.
	switch len(res.Templates) {
	case 1:
		// Auto-start in the background; redirect to run detail immediately
		// so the user sees logs streaming as docker pulls.
		go s.startRun(detachedContext(), res.RunID, res.Templates[0], res.ExtractDir)
		http.Redirect(w, r, "/run/"+res.RunID, http.StatusSeeOther)
	default:
		// >1 templates → picker page.
		http.Redirect(w, r, "/picker/"+res.RunID, http.StatusSeeOther)
	}
}

// --- /picker/{id} ---------------------------------------------------------

func (s *Server) handlePickerGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := db.GetRun(r.Context(), s.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	extractDir := s.Orch.ExtractDir(id)
	tpls, err := unraidxml.FindTemplates(extractDir)
	if err != nil || len(tpls) == 0 {
		http.Redirect(w, r, "/?err="+urlEncode("No templates found to pick from."), http.StatusSeeOther)
		return
	}
	// Each option's value is the XML path relative to the extract dir.
	type opt struct {
		RelPath    string
		Name       string
		Repository string
	}
	var options []opt
	for _, t := range tpls {
		rel, _ := filepath.Rel(extractDir, t.Path)
		options = append(options, opt{RelPath: rel, Name: t.Name, Repository: t.Repository})
	}
	s.renderPage(w, "Pick a template — RestoreRunner", "picker-content", map[string]any{
		"User":    auth.UserFromContext(r.Context()),
		"Run":     run,
		"Options": options,
	})
}

func (s *Server) handlePickerPost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	rel := r.FormValue("xml")
	if rel == "" {
		http.Redirect(w, r, "/picker/"+id, http.StatusSeeOther)
		return
	}
	extractDir := s.Orch.ExtractDir(id)
	// Resolve + validate the chosen path is inside the extract dir.
	abs, err := safeExtractPath(extractDir, rel)
	if err != nil {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	tpl, err := unraidxml.Parse(abs)
	if err != nil {
		http.Error(w, "template parse: "+err.Error(), http.StatusBadRequest)
		return
	}
	relXML, _ := filepath.Rel(extractDir, abs)
	if err := db.UpdateRunExtracted(r.Context(), s.DB, id, relXML, tpl.Repository); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	go s.startRun(detachedContext(), id, tpl, extractDir)
	http.Redirect(w, r, "/run/"+id, http.StatusSeeOther)
}

// safeExtractPath ensures the user-supplied relative path stays inside
// extractDir both lexically AND after symlink resolution. RAR is
// extracted via 7z which may preserve symlinks the archive contained;
// if one of those ever pointed out of extractDir, Parse() on the
// resolved path would read arbitrary host files. EvalSymlinks blocks
// that.
func safeExtractPath(extractDir, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return "", errors.New("unsafe path")
	}
	abs := filepath.Join(extractDir, rel)
	abs, err := filepath.Abs(abs)
	if err != nil {
		return "", err
	}
	absExtract, err := filepath.Abs(extractDir)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(abs+string(os.PathSeparator), absExtract+string(os.PathSeparator)) {
		return "", errors.New("path escapes extract dir")
	}
	// Defence-in-depth: resolve any symlinks and check we still live
	// inside the extract dir.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		absResolved, _ := filepath.Abs(resolved)
		if !strings.HasPrefix(absResolved+string(os.PathSeparator), absExtract+string(os.PathSeparator)) {
			return "", errors.New("symlink target escapes extract dir")
		}
	}
	return abs, nil
}

// --- run orchestration ----------------------------------------------------

// startRun pulls the image, starts the container, persists logs to disk,
// and schedules the auto-stop timeout. Runs in its own goroutine.
func (s *Server) startRun(ctx context.Context, runID string, tpl *unraidxml.Template, extractDir string) {
	opts := sandbox.RunOpts{
		ContainerName: "rr-" + runID,
		Template:      tpl,
		ExtractedDir:  extractDir,
		MemoryBytes:   s.MemoryBytes,
		CPUs:          s.CPUs,
	}
	startCtx, cancel := context.WithTimeout(ctx, 6*time.Minute) // covers image pull
	defer cancel()
	res, err := s.Sandbox.Run(startCtx, opts)
	if err != nil {
		s.Logger.Warn("run failed", "id", runID, "err", err)
		_ = db.UpdateRunFailed(context.Background(), s.DB, runID,
			friendlyDockerError(err))
		return
	}
	webui := unraidxml.ResolveWebUI(tpl.WebUI, "<host>", res.HostPort)
	if err := db.UpdateRunRunning(context.Background(), s.DB, runID,
		res.ContainerID, res.ContainerName, res.HostPort, webui); err != nil {
		s.Logger.Warn("mark running", "id", runID, "err", err)
	}

	// Start log persister. Reads from the live log stream and tees to
	// the on-disk log file. SSE endpoint can tail the file after the
	// container exits.
	go s.persistLogs(runID, res.ContainerID)

	// Schedule auto-stop.
	if s.RunTimeout > 0 {
		go func() {
			time.Sleep(s.RunTimeout)
			// Only stop if it's still marked running — user may have
			// stopped it manually already.
			if run, err := db.GetRun(context.Background(), s.DB, runID); err == nil && run.Status == "running" {
				s.Logger.Info("auto-stop timeout", "id", runID)
				_ = s.Sandbox.Stop(context.Background(), res.ContainerID)
				_ = db.UpdateRunStopped(context.Background(), s.DB, runID)
			}
		}()
	}
}

// persistLogs opens the container's log stream and writes it to the
// run's logs.txt. The file is append-mode so relaunch appends a new
// session. SSE readers will read from this file.
func (s *Server) persistLogs(runID, containerID string) {
	logPath := s.Orch.LogPath(runID)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		s.Logger.Warn("open log file", "err", err)
		return
	}
	defer f.Close()

	rc, err := s.Sandbox.Logs(context.Background(), containerID)
	if err != nil {
		_, _ = fmt.Fprintf(f, "\n[restore-runner] log stream error: %v\n", err)
		return
	}
	defer rc.Close()

	// Header so it's clear this is a new session in append-mode files.
	_, _ = fmt.Fprintf(f, "\n[restore-runner] session start %s container=%s\n",
		time.Now().UTC().Format(time.RFC3339), containerID[:12])
	_, _ = io.Copy(f, rc)
	_, _ = fmt.Fprintf(f, "\n[restore-runner] session end %s\n",
		time.Now().UTC().Format(time.RFC3339))
}

// friendlyDockerError turns a raw docker error into something a user can
// act on. We match common cases only; fallback is the raw error text.
func friendlyDockerError(err error) string {
	s := err.Error()
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "docker.sock") || strings.Contains(low, "no such file") && strings.Contains(low, "socket"):
		return "Docker socket not mounted — add `-v /var/run/docker.sock:/var/run/docker.sock` to your compose."
	case strings.Contains(low, "permission denied") && strings.Contains(low, "sock"):
		return "Docker socket mount is not writable — check the socket permissions on the host."
	case strings.Contains(low, "manifest unknown") || strings.Contains(low, "not found") && strings.Contains(low, "manifest"):
		return "Image not found on its registry — the XML's <Repository> may be wrong or the tag was removed upstream."
	case strings.Contains(low, "no route to host") || strings.Contains(low, "dial tcp") || strings.Contains(low, "timeout"):
		return "Couldn't reach the image registry — check the host's internet connection."
	}
	return s
}

// --- /run/{id} (detail) ---------------------------------------------------

func (s *Server) handleRunDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := db.GetRun(r.Context(), s.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, "Run "+run.OriginalName+" — RestoreRunner", "run-detail-content",
		map[string]any{
			"User": auth.UserFromContext(r.Context()),
			"Run":  run,
		})
}

// --- /run/{id}/logs (SSE) ------------------------------------------------

// handleRunLogs streams the log file + live tail via Server-Sent Events.
// Strategy:
//   1. Open logs.txt; send everything we have so far.
//   2. Keep reading; when we reach EOF, poll every ~500ms for new bytes.
//   3. Exit when the client disconnects OR the run leaves "running" and
//      we've drained the file.
func (s *Server) handleRunLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := db.GetRun(r.Context(), s.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	logPath := s.Orch.LogPath(id)
	f, err := os.OpenFile(logPath, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
		flusher.Flush()
		return
	}
	defer f.Close()

	// Hard cap on how long an SSE session can hold a goroutine open so
	// a stuck/walking-away client can't leak indefinitely.
	const sessionLimit = 2 * time.Hour
	deadline := time.Now().Add(sessionLimit)

	buf := make([]byte, 8192)
	for {
		if time.Now().After(deadline) {
			fmt.Fprintf(w, "event: end\ndata: session expired\n\n")
			flusher.Flush()
			return
		}
		select {
		case <-r.Context().Done():
			return
		default:
		}
		n, err := f.Read(buf)
		if n > 0 {
			// Escape newlines per SSE framing: one "data: " line per
			// physical line so the client gets a clean stream.
			for _, line := range splitLines(buf[:n]) {
				fmt.Fprintf(w, "data: %s\n\n", line)
			}
			flusher.Flush()
			continue
		}
		if err != nil && err != io.EOF {
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
			flusher.Flush()
			return
		}
		// EOF — check whether the run is still running. If not and we've
		// drained, close the stream.
		latest, _ := db.GetRun(r.Context(), s.DB, id)
		if latest != nil && latest.Status != "running" && latest.Status != "extracted" && latest.Status != "pending" {
			fmt.Fprintf(w, "event: end\ndata: %s\n\n", latest.Status)
			flusher.Flush()
			_ = run // keep run var used for templates elsewhere
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// splitLines returns SSE-safe chunks. Each input newline maps to a
// separate data event; embedded carriage returns are dropped.
func splitLines(b []byte) []string {
	s := strings.ReplaceAll(string(b), "\r", "")
	// Preserve empty-line breaks so log formatting survives.
	parts := strings.Split(s, "\n")
	return parts
}

// --- /run/{id}/stop -------------------------------------------------------

func (s *Server) handleRunStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := db.GetRun(r.Context(), s.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if run.ContainerID != "" {
		if err := s.Sandbox.Stop(r.Context(), run.ContainerID); err != nil {
			s.Logger.Warn("stop failed", "id", id, "err", err)
		}
	}
	_ = db.UpdateRunStopped(r.Context(), s.DB, id)
	http.Redirect(w, r, "/run/"+id, http.StatusSeeOther)
}

// --- /run/{id}/relaunch ---------------------------------------------------

// handleRunRelaunch re-runs a previously-extracted archive without asking
// the user to re-upload. Stops any currently-running container first.
func (s *Server) handleRunRelaunch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := db.GetRun(r.Context(), s.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	extractDir := s.Orch.ExtractDir(id)
	if run.XMLPath == "" {
		http.Error(w, "no XML recorded for this run", http.StatusBadRequest)
		return
	}
	abs, err := safeExtractPath(extractDir, run.XMLPath)
	if err != nil {
		http.Error(w, "bad xml path", http.StatusBadRequest)
		return
	}
	tpl, err := unraidxml.Parse(abs)
	if err != nil {
		http.Error(w, "parse xml: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Tear down any prior container.
	if run.ContainerID != "" {
		_ = s.Sandbox.Stop(r.Context(), run.ContainerID)
	}
	go s.startRun(detachedContext(), id, tpl, extractDir)
	http.Redirect(w, r, "/run/"+id, http.StatusSeeOther)
}

// --- /run/{id}/delete -----------------------------------------------------

func (s *Server) handleRunDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := db.GetRun(r.Context(), s.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if run.ContainerID != "" && run.Status == "running" {
		_ = s.Sandbox.Stop(r.Context(), run.ContainerID)
	}
	_ = s.Orch.DeleteRunFiles(id)
	_ = db.DeleteRun(r.Context(), s.DB, id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- helpers --------------------------------------------------------------

func (s *Server) renderPage(w http.ResponseWriter, title, bodyTemplate string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = title
	data["Body"] = bodyTemplate
	if _, hasUser := data["User"]; !hasUser {
		data["User"] = nil
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.Logger.Error("render", "body", bodyTemplate, "err", err)
	}
}

// urlEncode: minimal query-string escaper (we only use it for flash
// messages which we control).
func urlEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteString("%" + strconv.FormatInt(int64(c), 16))
		}
	}
	return b.String()
}
