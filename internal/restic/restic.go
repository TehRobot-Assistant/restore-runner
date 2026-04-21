// Package restic wraps the restic binary for the operations RestoreRunner
// needs: list the latest snapshot, and dump a single file from a snapshot
// to stdout so we can hash it without materialising a full restore.
//
// All invocations use exec.CommandContext with an arg slice — never a
// shell string — so attacker-influenced values (repo URL, source_path,
// rel_path) can't inject flags or shell metacharacters. The password is
// passed via the RESTIC_PASSWORD env var, never on the command line.
package restic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Adapter is the tiny surface RestoreRunner uses. Construct one per
// repo using NewAdapter and reuse.
type Adapter struct {
	binary   string
	repoURL  string
	password string
}

// NewAdapter locates the restic binary in PATH and returns an adapter
// bound to a specific repo + password. password may be empty for
// pwfile-based repos (not supported in v0.1).
func NewAdapter(repoURL, password string) (*Adapter, error) {
	path, err := exec.LookPath("restic")
	if err != nil {
		return nil, fmt.Errorf("restic not found on PATH — install it in the image: %w", err)
	}
	return &Adapter{binary: path, repoURL: repoURL, password: password}, nil
}

// Snapshot is a restic snapshot record, trimmed to the fields we use.
type Snapshot struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"short_id"`
	Time     time.Time `json:"time"`
	Paths    []string  `json:"paths"`
	Hostname string    `json:"hostname"`
}

// LatestSnapshot returns the most recent snapshot (by time). Returns
// (nil, nil) if the repo has no snapshots yet.
func (a *Adapter) LatestSnapshot(ctx context.Context) (*Snapshot, error) {
	cmd := a.exec(ctx, "snapshots", "--json", "--latest", "1")
	out, err := runCapture(cmd)
	if err != nil {
		return nil, err
	}
	var snaps []Snapshot
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("restic snapshots json: %w", err)
	}
	if len(snaps) == 0 {
		return nil, nil
	}
	return &snaps[0], nil
}

// CheckAccess runs `restic cat config` — a cheap round-trip that proves
// we can reach the repo AND the password is correct. Used during repo
// enrollment to fail fast on bad credentials.
func (a *Adapter) CheckAccess(ctx context.Context) error {
	cmd := a.exec(ctx, "cat", "config")
	if _, err := runCapture(cmd); err != nil {
		return err
	}
	return nil
}

// Dump streams a single file from a snapshot to w. Restic expects
// paths *as they are in the snapshot* (absolute, matching what
// restic saw at backup time). The rehearsal engine joins source_path
// + rel_path to get that.
//
// Restic's dump emits a tar when given a directory; for a single file
// it emits the raw bytes — which is what we want for hashing.
func (a *Adapter) Dump(ctx context.Context, snapshotID, absPath string, w io.Writer) error {
	// Guard against empty path / snapshot — restic would error but the
	// error is opaque. Fail early with a sensible message.
	if snapshotID == "" || absPath == "" {
		return fmt.Errorf("dump: snapshotID and absPath required")
	}
	cmd := a.exec(ctx, "dump", snapshotID, absPath)
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restic dump %s %s: %w: %s", snapshotID, absPath, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// exec builds a *exec.Cmd with the repo URL + password env set.
//
// Env is a minimal explicit slice — we deliberately do NOT inherit the
// container process's environment. The host could have other
// AWS_ACCESS_KEY_ID / RESTIC_REPOSITORY / B2_ACCOUNT_KEY / etc.
// variables set (e.g. for a different backup job or for apprise), and
// inheriting them into every restic invocation would silently redirect
// or authenticate against repos the user didn't ask us to touch.
func (a *Adapter) exec(ctx context.Context, args ...string) *exec.Cmd {
	all := append([]string{"--repo", a.repoURL, "--quiet"}, args...)
	cmd := exec.CommandContext(ctx, a.binary, all...)
	cmd.Env = []string{
		"HOME=/root",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"RESTIC_PASSWORD=" + a.password,
	}
	return cmd
}

// runCapture runs the command and returns stdout. Non-zero exit is
// wrapped with stderr so the web UI can surface a useful error.
func runCapture(cmd *exec.Cmd) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
