// Package baseline captures a point-in-time inventory of a source
// directory: every file's path, size, mtime, and SHA-256 hash. This is
// the reference that rehearsals compare restored files against —
// deliberately NOT the live filesystem, because that can change (or
// silently go empty, the rsync-disaster scenario the red-team flagged).
//
// Mutable files (matching exclude_globs) are recorded with their size +
// mtime but NOT hashed, and are excluded from rehearsal sampling. Logs,
// databases, and sqlite files can't meaningfully be diffed against a
// fixed hash.
package baseline

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultMutableGlobs is the out-of-the-box exclusion list. Anything
// matching these is still recorded for structural checks (count + size)
// but is not hashed and not sampled.
var DefaultMutableGlobs = []string{
	"*.db", "*.sqlite", "*.sqlite3", "*.sqlite-journal",
	"*.log", "*.log.*",
	"*.pid",
	"*.tmp", "*.swp", "*.swo",
	".DS_Store",
}

// Capture walks srcPath, records every file in the baseline_files
// table scoped to repoID, and writes a summary row to baselines.
// progress (may be nil) is called with every file for UI feedback.
//
// Deletes any prior baseline for repoID first — capture is atomic
// from the caller's POV.
func Capture(ctx context.Context, d *sql.DB, repoID int64, srcPath string, excludeGlobs []string, progress func(path string, size int64)) error {
	srcPath = filepath.Clean(srcPath)
	info, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("source path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source path is not a directory: %s", srcPath)
	}

	// Merge user globs with defaults. Empty entries silently dropped.
	globs := make([]string, 0, len(DefaultMutableGlobs)+len(excludeGlobs))
	for _, g := range DefaultMutableGlobs {
		globs = append(globs, g)
	}
	for _, g := range excludeGlobs {
		g = strings.TrimSpace(g)
		if g != "" {
			globs = append(globs, g)
		}
	}

	start := time.Now()

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM baseline_files WHERE repo_id=?`, repoID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM baselines WHERE repo_id=?`, repoID); err != nil {
		return err
	}

	insert, err := tx.PrepareContext(ctx, `
		INSERT INTO baseline_files (repo_id, rel_path, size_bytes, mtime_unix, sha256_hex, is_mutable)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer insert.Close()

	var fileCount, hashableCount int64
	var totalBytes int64

	err = filepath.WalkDir(srcPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Don't abort whole capture on a single permission error.
			// Log via progress and continue.
			if progress != nil {
				progress(path+" [SKIP "+walkErr.Error()+"]", 0)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks, devices, sockets, fifos
		}
		rel, err := filepath.Rel(srcPath, path)
		if err != nil {
			return nil
		}
		finfo, err := d.Info()
		if err != nil {
			return nil
		}
		mutable := matchesAny(rel, globs)

		var hashHex string
		if !mutable {
			h, err := hashFile(path)
			if err != nil {
				// Couldn't hash — record as mutable so it's excluded from
				// rehearsals rather than blowing up the whole capture.
				mutable = true
			} else {
				hashHex = h
			}
		}

		if _, err := insert.ExecContext(ctx, repoID, rel, finfo.Size(), finfo.ModTime().Unix(), hashHex, boolToInt(mutable)); err != nil {
			return err
		}
		fileCount++
		totalBytes += finfo.Size()
		if !mutable {
			hashableCount++
		}
		if progress != nil {
			progress(rel, finfo.Size())
		}
		return nil
	})
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO baselines (repo_id, captured_at, file_count, total_bytes, hashable_count, duration_seconds)
		VALUES (?, ?, ?, ?, ?, ?)
	`, repoID, time.Now().Unix(), fileCount, totalBytes, hashableCount, int64(time.Since(start).Seconds())); err != nil {
		return err
	}

	return tx.Commit()
}

// matchesAny returns true if either the basename or the full relative
// path matches any of the supplied globs. Checking both lets a user
// write either a basename pattern (`*.log`) or a path pattern
// (`cache/*`) and have it work. filepath.Match is non-recursive — `**`
// is not supported; tree-wide exclusions need an explicit path prefix.
func matchesAny(relPath string, globs []string) bool {
	base := filepath.Base(relPath)
	for _, g := range globs {
		if ok, _ := filepath.Match(g, base); ok {
			return true
		}
		if ok, _ := filepath.Match(g, relPath); ok {
			return true
		}
	}
	return false
}

// hashFile streams a file through SHA-256. Buffer sized for modern
// filesystems — larger than the default bufio read to reduce syscalls.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 256*1024)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
