package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Run represents a single uploaded archive + its lifecycle.
type Run struct {
	ID            string
	OriginalName  string
	SizeBytes     int64
	UploadedAt    time.Time
	ExtractedAt   time.Time
	XMLPath       string // relative path within extract dir, or "" if none
	Image         string
	ContainerID   string
	ContainerName string
	HostPort      int
	WebUIURL      string
	Status        string // pending|extracted|running|stopped|failed
	Error         string
	StartedAt     time.Time
	StoppedAt     time.Time
}

// CreateRun inserts a fresh run row, returns it.
func CreateRun(ctx context.Context, d *sql.DB, id, originalName string, sizeBytes int64) (*Run, error) {
	now := time.Now()
	_, err := d.ExecContext(ctx, `
		INSERT INTO runs(id, original_name, size_bytes, uploaded_at, status)
		VALUES (?,?,?,?,?)`,
		id, originalName, sizeBytes, now.Unix(), "pending")
	if err != nil {
		return nil, err
	}
	return &Run{
		ID: id, OriginalName: originalName, SizeBytes: sizeBytes,
		UploadedAt: now, Status: "pending",
	}, nil
}

// GetRun fetches a single run by id.
func GetRun(ctx context.Context, d *sql.DB, id string) (*Run, error) {
	row := d.QueryRowContext(ctx, `
		SELECT id, original_name, size_bytes, uploaded_at,
		       COALESCE(extracted_at, 0), COALESCE(xml_path, ''),
		       COALESCE(image, ''), COALESCE(container_id, ''),
		       COALESCE(container_name, ''), COALESCE(host_port, 0),
		       COALESCE(webui_url, ''), status, COALESCE(error, ''),
		       COALESCE(started_at, 0), COALESCE(stopped_at, 0)
		FROM runs WHERE id = ?`, id)
	var r Run
	var uploaded, extracted, started, stopped int64
	if err := row.Scan(
		&r.ID, &r.OriginalName, &r.SizeBytes, &uploaded,
		&extracted, &r.XMLPath,
		&r.Image, &r.ContainerID, &r.ContainerName, &r.HostPort,
		&r.WebUIURL, &r.Status, &r.Error,
		&started, &stopped,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.UploadedAt = time.Unix(uploaded, 0)
	if extracted > 0 {
		r.ExtractedAt = time.Unix(extracted, 0)
	}
	if started > 0 {
		r.StartedAt = time.Unix(started, 0)
	}
	if stopped > 0 {
		r.StoppedAt = time.Unix(stopped, 0)
	}
	return &r, nil
}

// ListRuns returns all runs newest-first.
func ListRuns(ctx context.Context, d *sql.DB) ([]*Run, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT id, original_name, size_bytes, uploaded_at,
		       COALESCE(extracted_at, 0), COALESCE(xml_path, ''),
		       COALESCE(image, ''), COALESCE(container_id, ''),
		       COALESCE(container_name, ''), COALESCE(host_port, 0),
		       COALESCE(webui_url, ''), status, COALESCE(error, ''),
		       COALESCE(started_at, 0), COALESCE(stopped_at, 0)
		FROM runs ORDER BY uploaded_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Run
	for rows.Next() {
		var r Run
		var uploaded, extracted, started, stopped int64
		if err := rows.Scan(
			&r.ID, &r.OriginalName, &r.SizeBytes, &uploaded,
			&extracted, &r.XMLPath,
			&r.Image, &r.ContainerID, &r.ContainerName, &r.HostPort,
			&r.WebUIURL, &r.Status, &r.Error,
			&started, &stopped,
		); err != nil {
			continue
		}
		r.UploadedAt = time.Unix(uploaded, 0)
		if extracted > 0 {
			r.ExtractedAt = time.Unix(extracted, 0)
		}
		if started > 0 {
			r.StartedAt = time.Unix(started, 0)
		}
		if stopped > 0 {
			r.StoppedAt = time.Unix(stopped, 0)
		}
		out = append(out, &r)
	}
	return out, nil
}

// UpdateRunExtracted marks a run as extracted with its XML metadata.
func UpdateRunExtracted(ctx context.Context, d *sql.DB, id, xmlPath, image string) error {
	_, err := d.ExecContext(ctx, `
		UPDATE runs SET extracted_at = ?, xml_path = ?, image = ?, status = 'extracted', error = ''
		WHERE id = ?`,
		time.Now().Unix(), xmlPath, image, id)
	return err
}

// UpdateRunRunning marks a run as started.
func UpdateRunRunning(ctx context.Context, d *sql.DB, id, containerID, containerName string, hostPort int, webUI string) error {
	_, err := d.ExecContext(ctx, `
		UPDATE runs SET container_id = ?, container_name = ?, host_port = ?, webui_url = ?,
		                started_at = ?, status = 'running', error = ''
		WHERE id = ?`,
		containerID, containerName, hostPort, webUI,
		time.Now().Unix(), id)
	return err
}

// UpdateRunStopped marks a run as stopped.
func UpdateRunStopped(ctx context.Context, d *sql.DB, id string) error {
	_, err := d.ExecContext(ctx, `
		UPDATE runs SET stopped_at = ?, status = 'stopped'
		WHERE id = ?`,
		time.Now().Unix(), id)
	return err
}

// UpdateRunFailed marks a run as failed with an error message.
func UpdateRunFailed(ctx context.Context, d *sql.DB, id, errMsg string) error {
	_, err := d.ExecContext(ctx, `
		UPDATE runs SET status = 'failed', error = ?, stopped_at = ?
		WHERE id = ?`,
		errMsg, time.Now().Unix(), id)
	return err
}

// DeleteRun removes a run row.
func DeleteRun(ctx context.Context, d *sql.DB, id string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM runs WHERE id = ?`, id)
	return err
}

// ListRunningRunIDs returns the UUIDs of every run currently marked
// as running. Used on startup to sweep orphans.
func ListRunningRunIDs(ctx context.Context, d *sql.DB) ([]string, error) {
	rows, err := d.QueryContext(ctx, `SELECT id FROM runs WHERE status = 'running'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out, nil
}
