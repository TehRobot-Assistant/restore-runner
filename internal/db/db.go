// Package db owns the SQLite store for RestoreRunner. The only "app data"
// we persist is: users, sessions, and the runs table (one row per uploaded
// archive). Everything else (extracted files, docker state, live logs) is
// ephemeral or filesystem-backed.
package db

import (
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go driver
)

// ErrNotFound signals "no row matched".
var ErrNotFound = errors.New("not found")

// Open opens the SQLite file and runs migrations.
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
	`CREATE TABLE IF NOT EXISTS users (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		username         TEXT    NOT NULL UNIQUE,
		password_hash    TEXT    NOT NULL,
		must_change      INTEGER NOT NULL DEFAULT 0,
		created_at       INTEGER NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS sessions (
		token         TEXT    PRIMARY KEY,
		user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		created_at    INTEGER NOT NULL,
		expires_at    INTEGER NOT NULL,
		last_used_at  INTEGER NOT NULL
	)`,

	// Each row = one uploaded archive. The extracted dir + logs.txt are
	// keyed off this UUID. status transitions: pending → extracted →
	// running → stopped | failed.
	`CREATE TABLE IF NOT EXISTS runs (
		id               TEXT    PRIMARY KEY,     -- uuid
		original_name    TEXT    NOT NULL,        -- the uploaded filename
		size_bytes       INTEGER NOT NULL,
		uploaded_at      INTEGER NOT NULL,
		extracted_at     INTEGER,
		xml_path         TEXT,                    -- relative to extract dir
		image            TEXT,                    -- docker image from the XML
		container_id     TEXT,                    -- docker container id when running
		container_name   TEXT,                    -- rr-<uuid>
		host_port        INTEGER,                 -- host port mapped to container
		webui_url        TEXT,                    -- parsed from <WebUI>, ports substituted
		status           TEXT NOT NULL,           -- pending|extracted|running|stopped|failed
		error            TEXT,
		started_at       INTEGER,
		stopped_at       INTEGER
	)`,
	`CREATE INDEX IF NOT EXISTS idx_runs_uploaded ON runs (uploaded_at DESC)`,
}
