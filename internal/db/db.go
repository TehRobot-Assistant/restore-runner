// Package db owns the SQLite store. Everything RestoreRunner needs long-term
// — users, settings, backup repos, baselines, rehearsals, actions — lives
// here. No YAML config; all state in one file under /config.
package db

import (
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go driver, cross-compiles to ARM without CGO
)

// ErrNotFound signals "no row matched" in a friendly way.
var ErrNotFound = errors.New("not found")

// Open opens the SQLite file and runs all migrations. Safe to call on an
// empty file — the migrations create the schema from scratch.
func Open(path string) (*sql.DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	d.SetMaxOpenConns(4)
	d.SetMaxIdleConns(2)
	if err := d.Ping(); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := migrate(d); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

func migrate(d *sql.DB) error {
	for i, stmt := range schema {
		if _, err := d.Exec(stmt); err != nil {
			return fmt.Errorf("migration %d: %w\nSQL: %s", i, err, stmt)
		}
	}
	return nil
}

var schema = []string{
	// --- Admin user(s). v0.1 has exactly one admin; leaving room for more. ---
	`CREATE TABLE IF NOT EXISTS users (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		username         TEXT    NOT NULL UNIQUE,
		password_hash    TEXT    NOT NULL,
		must_change      INTEGER NOT NULL DEFAULT 0,
		created_at       INTEGER NOT NULL
	)`,

	// --- Session cookies for the web UI. Cleaned up on logout + periodically. ---
	`CREATE TABLE IF NOT EXISTS sessions (
		token         TEXT    PRIMARY KEY,
		user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		created_at    INTEGER NOT NULL,
		expires_at    INTEGER NOT NULL,
		last_used_at  INTEGER NOT NULL
	)`,

	// --- Arbitrary key/value settings (default cadence, apprise URLs, etc). ---
	`CREATE TABLE IF NOT EXISTS settings (
		key    TEXT PRIMARY KEY,
		value  TEXT NOT NULL
	)`,

	// --- Backup repositories enrolled in RestoreRunner. Each has a type
	// (restic/borg/kopia), a URL, an encrypted password blob, and a source
	// path that the baseline was captured from. ---
	`CREATE TABLE IF NOT EXISTS repos (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		name              TEXT    NOT NULL UNIQUE,
		kind              TEXT    NOT NULL,         -- 'restic' | 'borg' | 'kopia'
		repo_url          TEXT    NOT NULL,         -- local path, sftp URL, s3 URL, etc
		password_enc      TEXT,                      -- encrypted with master key; blank for keyfile
		source_path       TEXT    NOT NULL,         -- filesystem path the baseline was captured from
		sample_size       INTEGER NOT NULL DEFAULT 30, -- files per rehearsal
		cadence_hours     INTEGER NOT NULL DEFAULT 168, -- 168h = weekly
		exclude_globs     TEXT    NOT NULL DEFAULT '', -- newline-separated glob patterns
		last_rehearsed_at INTEGER NOT NULL DEFAULT 0,
		last_status       TEXT    NOT NULL DEFAULT '', -- '' | 'pass' | 'degraded' | 'fail'
		enabled           INTEGER NOT NULL DEFAULT 1,
		created_at        INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_repos_enabled ON repos (enabled, last_rehearsed_at)`,

	// --- Baseline file inventory per repo. Captured at enrollment and on
	// demand via "Recapture baseline". Rehearsals compare restored files
	// against this fixed snapshot, NOT against the live source (red-team
	// fix: live comparison misses rsync-empty-folder). ---
	`CREATE TABLE IF NOT EXISTS baseline_files (
		repo_id          INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
		rel_path         TEXT    NOT NULL,           -- path relative to source_path
		size_bytes       INTEGER NOT NULL,
		mtime_unix       INTEGER NOT NULL,
		sha256_hex       TEXT    NOT NULL,
		is_mutable       INTEGER NOT NULL DEFAULT 0, -- matches exclude_globs at capture
		PRIMARY KEY (repo_id, rel_path)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_baseline_repo_nonmut ON baseline_files (repo_id, is_mutable)`,

	// --- One row per baseline-capture event (metadata — total size, file
	// count, when it ran). Separate from baseline_files so we can show
	// "last recaptured N days ago" without a COUNT(*). ---
	`CREATE TABLE IF NOT EXISTS baselines (
		repo_id          INTEGER PRIMARY KEY REFERENCES repos(id) ON DELETE CASCADE,
		captured_at      INTEGER NOT NULL,
		file_count       INTEGER NOT NULL,
		total_bytes      INTEGER NOT NULL,
		hashable_count   INTEGER NOT NULL,  -- excluding mutable files
		duration_seconds INTEGER NOT NULL
	)`,

	// --- Rehearsal history. One row per run. ---
	`CREATE TABLE IF NOT EXISTS rehearsals (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		repo_id          INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
		started_at       INTEGER NOT NULL,
		finished_at      INTEGER NOT NULL DEFAULT 0,
		status           TEXT    NOT NULL,         -- 'running' | 'pass' | 'degraded' | 'fail'
		sampled_count    INTEGER NOT NULL DEFAULT 0,
		matched_count    INTEGER NOT NULL DEFAULT 0,
		diverged_count   INTEGER NOT NULL DEFAULT 0,
		missing_count    INTEGER NOT NULL DEFAULT 0,
		live_file_count  INTEGER NOT NULL DEFAULT 0,
		live_total_bytes INTEGER NOT NULL DEFAULT 0,
		structural_ok    INTEGER NOT NULL DEFAULT 1,
		detail           TEXT    NOT NULL DEFAULT '', -- human-readable summary; per-file detail in rehearsal_findings
		triggered_by     TEXT    NOT NULL DEFAULT ''  -- 'schedule' | 'manual' | user_id
	)`,
	`CREATE INDEX IF NOT EXISTS idx_rehearsals_repo ON rehearsals (repo_id, started_at DESC)`,

	// --- Per-file findings for a rehearsal. Bounded by sample_size. ---
	`CREATE TABLE IF NOT EXISTS rehearsal_findings (
		rehearsal_id     INTEGER NOT NULL REFERENCES rehearsals(id) ON DELETE CASCADE,
		rel_path         TEXT    NOT NULL,
		outcome          TEXT    NOT NULL,   -- 'match' | 'diverge' | 'missing' | 'restore-error'
		expected_sha     TEXT,
		actual_sha       TEXT,
		note             TEXT,
		PRIMARY KEY (rehearsal_id, rel_path)
	)`,

	// --- Audit log. ---
	`CREATE TABLE IF NOT EXISTS actions (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		repo_id          INTEGER,
		user_id          INTEGER,
		action           TEXT NOT NULL,    -- 'enroll' | 'rehearse' | 'recapture' | 'disable' | 'delete'
		detail           TEXT,
		created_at       INTEGER NOT NULL
	)`,
}
