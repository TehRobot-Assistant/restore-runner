// Package rehearse runs the core backup-verification loop:
//
//  1. Pick N random non-mutable files from the baseline.
//  2. Restore each from the backup (via the Restic adapter) into an
//     ephemeral 0700 scratch dir.
//  3. Hash the restored bytes; compare against the baseline hash.
//  4. Delete the scratch file immediately (don't let 20TB of temp data
//     accumulate during a long rehearsal).
//  5. In parallel, walk the *live* source dir and count files + total
//     bytes — compare to the baseline's totals. A large delta (e.g.
//     live has zero files, baseline has 50k) is the classic
//     rsync-wiped-its-own-source failure, and is flagged as a
//     structural failure even if every sampled file matches.
//
// Status semantics:
//
//	pass      — every sampled file matched the baseline AND structural
//	            check is within tolerance
//	degraded  — some files diverged or were missing from the backup
//	fail      — backup is unreachable, OR the structural check detected
//	            a source collapse / massive deletion
package rehearse

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"path/filepath"
	"time"

	"github.com/trstudios/restore-runner/internal/restic"
)

// Structural tolerance: we flag a structural failure when live file
// count is less than this fraction of baseline. 0.10 = "live has lost
// more than 90% of the files recorded in the baseline". Catches
// the rsync-empty-source case (0% remaining) without flagging a normal
// day's churn (losing a few files is expected).
const structuralCollapseThreshold = 0.10

// Result is the outcome the caller stores in the rehearsals table.
type Result struct {
	Status         string // "pass" | "degraded" | "fail"
	SampledCount   int
	MatchedCount   int
	DivergedCount  int
	MissingCount   int
	LiveFileCount  int64
	LiveTotalBytes int64
	StructuralOK   bool
	Detail         string
	Findings       []Finding
}

// Finding is one sampled file's outcome.
type Finding struct {
	RelPath     string
	Outcome     string // "match" | "diverge" | "missing" | "restore-error"
	ExpectedSHA string
	ActualSHA   string
	Note        string
}

// Run executes one rehearsal against the given repo. Reads baseline,
// samples, restores via the adapter, hashes, compares. Returns a full
// Result even on partial failure — the caller persists it.
func Run(ctx context.Context, d *sql.DB, repoID int64, sourcePath string, sampleSize int, scratchDir string, adapter *restic.Adapter) (*Result, error) {
	// Resolve the latest snapshot once. Missing = fail.
	snap, err := adapter.LatestSnapshot(ctx)
	if err != nil {
		return &Result{
			Status: "fail",
			Detail: "restic: " + err.Error(),
		}, nil
	}
	if snap == nil {
		return &Result{
			Status: "fail",
			Detail: "restic repo has no snapshots yet",
		}, nil
	}

	// Sample non-mutable baseline rows.
	sampled, err := sampleBaselinePaths(ctx, d, repoID, sampleSize)
	if err != nil {
		return nil, err
	}
	if len(sampled) == 0 {
		return &Result{
			Status: "fail",
			Detail: "baseline has no hashable files — recapture the baseline",
		}, nil
	}

	// scratchDir kept around as a setting knob for future v0.2 features
	// (e.g. verify-and-diff against a pre-restore copy), but the current
	// rehearsal streams restored bytes directly through SHA-256 and
	// discards them — no scratch files needed. This avoids writing 20GB
	// of restored-then-discarded data during a rehearsal on a big sample.
	_ = scratchDir

	res := &Result{
		SampledCount: len(sampled),
		StructuralOK: true,
	}

	// Per-file restore + hash loop.
	for _, b := range sampled {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		absPath := filepath.Join(sourcePath, b.RelPath)
		if err := restoreAndHash(ctx, adapter, snap.ID, absPath, &b, res); err != nil {
			// structural errors propagate up via res.Findings — keep
			// going so we see the full sample, not just the first failure.
			continue
		}
	}

	// Structural check — walk live source.
	lc, lb := walkLive(sourcePath)
	res.LiveFileCount = lc
	res.LiveTotalBytes = lb

	// Pull the baseline totals for comparison.
	var baselineFiles int64
	_ = d.QueryRowContext(ctx, `SELECT file_count FROM baselines WHERE repo_id=?`, repoID).Scan(&baselineFiles)

	if baselineFiles > 0 {
		ratio := float64(lc) / float64(baselineFiles)
		if ratio < structuralCollapseThreshold {
			res.StructuralOK = false
			res.Detail = fmt.Sprintf("source collapse detected: live has %d files vs baseline %d (%.1f%%)",
				lc, baselineFiles, ratio*100)
		}
	}

	res.Status = decideStatus(res)
	if res.Status == "pass" && res.Detail == "" {
		res.Detail = fmt.Sprintf("%d/%d sampled files matched; live %d files", res.MatchedCount, res.SampledCount, lc)
	}
	return res, nil
}

type baselineRow struct {
	RelPath string
	Size    int64
	SHA     string
}

// sampleBaselinePaths picks up to n random non-mutable rows. Uses
// SQLite's RANDOM() — fine for < 1M baseline rows, instant in practice.
func sampleBaselinePaths(ctx context.Context, d *sql.DB, repoID int64, n int) ([]baselineRow, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT rel_path, size_bytes, sha256_hex
		FROM baseline_files
		WHERE repo_id = ? AND is_mutable = 0 AND sha256_hex != ''
		ORDER BY RANDOM()
		LIMIT ?`, repoID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []baselineRow
	for rows.Next() {
		var b baselineRow
		if err := rows.Scan(&b.RelPath, &b.Size, &b.SHA); err == nil {
			out = append(out, b)
		}
	}
	// Shuffle one more time client-side so callers can't detect insertion
	// order from SQLite's RANDOM() being deterministic per query plan.
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out, nil
}

// restoreAndHash streams one file from the backup directly through a
// SHA-256 hasher — no scratch file — and compares the result to the
// baseline hash. Avoids materialising potentially-huge restored files
// on disk just to read them back and discard.
func restoreAndHash(ctx context.Context, adapter *restic.Adapter, snapshotID, absPath string, b *baselineRow, res *Result) error {
	h := sha256.New()
	if err := adapter.Dump(ctx, snapshotID, absPath, h); err != nil {
		note := err.Error()
		outcome := "restore-error"
		if containsAny(note, "no such file", "not found", "does not exist") {
			outcome = "missing"
		}
		res.MissingCount++
		res.Findings = append(res.Findings, Finding{
			RelPath: b.RelPath, Outcome: outcome, ExpectedSHA: b.SHA, Note: note,
		})
		return err
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if actual == b.SHA {
		res.MatchedCount++
		res.Findings = append(res.Findings, Finding{
			RelPath: b.RelPath, Outcome: "match", ExpectedSHA: b.SHA, ActualSHA: actual,
		})
	} else {
		res.DivergedCount++
		res.Findings = append(res.Findings, Finding{
			RelPath: b.RelPath, Outcome: "diverge", ExpectedSHA: b.SHA, ActualSHA: actual,
		})
	}
	return nil
}

// walkLive counts regular files + total bytes in the source directory.
// Doesn't re-hash — hashing 20TB every rehearsal would make this useless.
// Structural check is about "did the source fall off a cliff", not
// detailed integrity.
func walkLive(sourcePath string) (count, bytes int64) {
	_ = filepath.WalkDir(sourcePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		count++
		bytes += info.Size()
		return nil
	})
	return
}

// decideStatus applies the status semantics documented at the top.
func decideStatus(r *Result) string {
	if !r.StructuralOK {
		return "fail"
	}
	if r.DivergedCount > 0 || r.MissingCount > 0 {
		return "degraded"
	}
	return "pass"
}

// containsAny — substring match against any needle. Lowercase both sides.
func containsAny(haystack string, needles ...string) bool {
	h := toLower(haystack)
	for _, n := range needles {
		if indexOf(h, toLower(n)) >= 0 {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return string(out)
}

func indexOf(haystack, needle string) int {
	if needle == "" {
		return 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// PersistResult writes the rehearsal row + all findings. Call after Run.
func PersistResult(ctx context.Context, d *sql.DB, repoID int64, startedAt time.Time, triggeredBy string, res *Result) (int64, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	ins := tx.QueryRowContext(ctx, `
		INSERT INTO rehearsals (repo_id, started_at, finished_at, status,
		                        sampled_count, matched_count, diverged_count, missing_count,
		                        live_file_count, live_total_bytes, structural_ok,
		                        detail, triggered_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING id
	`, repoID, startedAt.Unix(), time.Now().Unix(), res.Status,
		res.SampledCount, res.MatchedCount, res.DivergedCount, res.MissingCount,
		res.LiveFileCount, res.LiveTotalBytes, boolToInt(res.StructuralOK),
		res.Detail, triggeredBy)

	var rehearsalID int64
	if err := ins.Scan(&rehearsalID); err != nil {
		return 0, fmt.Errorf("insert rehearsal: %w", err)
	}

	findingInsert, err := tx.PrepareContext(ctx, `
		INSERT INTO rehearsal_findings (rehearsal_id, rel_path, outcome, expected_sha, actual_sha, note)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, err
	}
	defer findingInsert.Close()
	for _, f := range res.Findings {
		if _, err := findingInsert.ExecContext(ctx, rehearsalID, f.RelPath, f.Outcome, f.ExpectedSHA, f.ActualSHA, f.Note); err != nil {
			return 0, err
		}
	}

	// Reflect latest status on the repo row so the dashboard is 1 query.
	if _, err := tx.ExecContext(ctx, `
		UPDATE repos SET last_rehearsed_at=?, last_status=? WHERE id=?
	`, time.Now().Unix(), res.Status, repoID); err != nil {
		return 0, err
	}

	// Audit.
	_, _ = tx.ExecContext(ctx, `
		INSERT INTO actions (repo_id, action, detail, created_at)
		VALUES (?, 'rehearse', ?, ?)
	`, repoID, fmt.Sprintf("%s: %s", res.Status, res.Detail), time.Now().Unix())

	return rehearsalID, tx.Commit()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
