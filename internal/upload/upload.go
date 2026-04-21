// Package upload owns the multipart upload stream + the end-to-end
// orchestration that happens after bytes land on disk:
//
//   1. Stream the archive to /config/uploads/<uuid>/archive.<ext>
//   2. Extract it to /config/uploads/<uuid>/extracted/
//   3. Scan the extract tree for Unraid XML templates
//   4. Insert the DB row (status=pending → extracted)
//
// The actual docker-run step is triggered separately by the web handler
// once the user (or single-template auto-resolve) picks the template.
package upload

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/trstudios/restore-runner/internal/archive"
	"github.com/trstudios/restore-runner/internal/db"
	"github.com/trstudios/restore-runner/internal/unraidxml"
)

// ErrNoXML is returned when the uploaded archive doesn't contain any
// parseable Unraid XML template. Caller shows a friendly error page.
var ErrNoXML = errors.New("archive contains no Unraid container template (*.xml)")

// ErrTooLarge is returned when the upload exceeds the configured cap.
var ErrTooLarge = errors.New("upload exceeds size cap")

// ErrUnsupportedFormat is returned when we can't detect the archive format
// from the filename extension.
var ErrUnsupportedFormat = errors.New("unsupported archive format")

// Result is what the orchestrator returns after a successful upload +
// extract + scan.
type Result struct {
	RunID         string
	ExtractDir    string            // absolute path of the extract root
	Templates     []*unraidxml.Template
}

// Orchestrator encapsulates the upload → extract → scan pipeline.
// All filesystem paths are computed relative to BaseDir (typically
// /config/uploads in the running container).
type Orchestrator struct {
	DB           *sql.DB
	BaseDir      string
	MaxBytes     int64 // hard cap per upload
}

// Handle consumes the multipart request body, writes the archive to a
// fresh UUID-keyed directory, extracts it, scans for XML, and returns
// either the list of templates (0..N) so the caller can route the
// next step.
//
// Uses r.MultipartReader() (not ParseMultipartForm) so multi-GB uploads
// stream through to disk without buffering in memory.
func (o *Orchestrator) Handle(r *http.Request) (*Result, error) {
	// Validate Content-Length ahead of streaming if the client set one,
	// so we reject comically large uploads before opening the reader.
	if r.ContentLength > 0 && r.ContentLength > o.MaxBytes {
		return nil, ErrTooLarge
	}

	mr, err := r.MultipartReader()
	if err != nil {
		return nil, fmt.Errorf("multipart reader: %w", err)
	}

	runID := uuid.New().String()
	runDir := filepath.Join(o.BaseDir, runID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir run: %w", err)
	}
	extractDir := filepath.Join(runDir, "extracted")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir extract: %w", err)
	}

	// Iterate parts. We only care about the first file part named
	// "archive"; everything else is ignored (but drained).
	var (
		originalName string
		savedPath    string
		size         int64
		format       string
	)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			o.cleanupRun(runID)
			return nil, fmt.Errorf("next part: %w", err)
		}
		if part.FormName() != "archive" || part.FileName() == "" {
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}
		originalName = filepath.Base(part.FileName())
		format = archive.DetectFormat(originalName)
		if format == "" {
			_ = part.Close()
			o.cleanupRun(runID)
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, originalName)
		}
		savedPath = filepath.Join(runDir, "archive."+fileExtForFormat(format))
		out, err := os.OpenFile(savedPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			_ = part.Close()
			o.cleanupRun(runID)
			return nil, fmt.Errorf("create archive file: %w", err)
		}
		// Cap writes at MaxBytes+1; if we see +1 extra byte, reject.
		n, copyErr := io.Copy(out, io.LimitReader(part, o.MaxBytes+1))
		_ = out.Close()
		_ = part.Close()
		if copyErr != nil {
			o.cleanupRun(runID)
			return nil, fmt.Errorf("write archive: %w", copyErr)
		}
		if n > o.MaxBytes {
			o.cleanupRun(runID)
			return nil, ErrTooLarge
		}
		size = n
		break
	}
	if savedPath == "" {
		o.cleanupRun(runID)
		return nil, errors.New("no archive file in upload")
	}

	// DB row first so if extraction fails we have a record of the failure.
	if _, err := db.CreateRun(r.Context(), o.DB, runID, originalName, size); err != nil {
		o.cleanupRun(runID)
		return nil, fmt.Errorf("create run row: %w", err)
	}

	// Extract.
	if err := archive.Extract(savedPath, extractDir, format); err != nil {
		_ = db.UpdateRunFailed(r.Context(), o.DB, runID, "extract: "+err.Error())
		return nil, fmt.Errorf("extract: %w", err)
	}

	// Scan for Unraid XML templates.
	tpls, err := unraidxml.FindTemplates(extractDir)
	if err != nil {
		_ = db.UpdateRunFailed(r.Context(), o.DB, runID, "scan xml: "+err.Error())
		return nil, fmt.Errorf("scan xml: %w", err)
	}
	if len(tpls) == 0 {
		_ = db.UpdateRunFailed(r.Context(), o.DB, runID, ErrNoXML.Error())
		return &Result{RunID: runID, ExtractDir: extractDir, Templates: nil}, ErrNoXML
	}

	// Single-template case: mark extracted + record image now.
	if len(tpls) == 1 {
		relXML, _ := filepath.Rel(extractDir, tpls[0].Path)
		_ = db.UpdateRunExtracted(r.Context(), o.DB, runID, relXML, tpls[0].Repository)
	}

	return &Result{RunID: runID, ExtractDir: extractDir, Templates: tpls}, nil
}

// cleanupRun wipes the run directory on a failure before we've committed
// the DB row. Best-effort.
func (o *Orchestrator) cleanupRun(runID string) {
	_ = os.RemoveAll(filepath.Join(o.BaseDir, runID))
}

// RunDir returns the absolute path of a run's directory.
func (o *Orchestrator) RunDir(runID string) string {
	return filepath.Join(o.BaseDir, runID)
}

// ExtractDir returns the absolute path of a run's extracted tree.
func (o *Orchestrator) ExtractDir(runID string) string {
	return filepath.Join(o.BaseDir, runID, "extracted")
}

// LogPath returns the on-disk path for a run's persisted log file.
func (o *Orchestrator) LogPath(runID string) string {
	return filepath.Join(o.BaseDir, runID, "logs.txt")
}

// DeleteRunFiles removes a run's on-disk extract + archive. DB row is
// the caller's responsibility.
func (o *Orchestrator) DeleteRunFiles(runID string) error {
	return os.RemoveAll(filepath.Join(o.BaseDir, runID))
}

// fileExtForFormat maps our canonical format tag back to the on-disk
// extension we use for the archive file. The suffix isn't parsed later —
// we already know the format from the HTTP flow — but it helps debuggers.
func fileExtForFormat(format string) string {
	switch format {
	case "zip":
		return "zip"
	case "tar":
		return "tar"
	case "tar.gz":
		return "tar.gz"
	case "tar.zst":
		return "tar.zst"
	case "rar":
		return "rar"
	default:
		return "bin"
	}
}

// CleanupOldRuns walks BaseDir and removes any run dir whose name is
// a UUID not present in the keep set. Called on startup + periodically.
func (o *Orchestrator) CleanupOrphanDirs(keepIDs map[string]bool) error {
	entries, err := os.ReadDir(o.BaseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// Only touch UUID-shaped dirs.
		if len(name) != 36 || !strings.Contains(name, "-") {
			continue
		}
		if keepIDs[name] {
			continue
		}
		_ = os.RemoveAll(filepath.Join(o.BaseDir, name))
	}
	return nil
}
