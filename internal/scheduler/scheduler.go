// Package scheduler runs background rehearsals.
//
// One goroutine iterates enabled repos every minute and fires a rehearsal
// for any repo whose (last_rehearsed_at + cadence_hours * 3600) is in the
// past. A signal channel lets the web UI trigger an immediate sweep
// ("Run all now" — currently unused but wired for v0.2).
//
// Per-repo rehearsals run serially. A single restic binary scanning a
// remote repo already saturates network + CPU on a homelab host; running
// two at once just fights for I/O and doubles the wall time.
package scheduler

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/trstudios/restore-runner/internal/db"
	"github.com/trstudios/restore-runner/internal/notify"
	"github.com/trstudios/restore-runner/internal/rehearse"
	"github.com/trstudios/restore-runner/internal/restic"
)

// Scheduler coordinates background rehearsals.
type Scheduler struct {
	DB       *sql.DB
	Logger   *slog.Logger
	Notifier *notify.Client

	trigger  chan int64 // repo_id; 0 = sweep all due
	initOnce sync.Once
}

// TriggerRepo enqueues an immediate rehearsal for one repo. Safe from
// any goroutine. If the scheduler is busy, multiple calls for the same
// repo coalesce — the request just reschedules once.
func (s *Scheduler) TriggerRepo(repoID int64) {
	s.ensureChan()
	select {
	case s.trigger <- repoID:
	default:
		// Queue full — a rehearsal is already pending. Drop.
	}
}

func (s *Scheduler) ensureChan() {
	s.initOnce.Do(func() {
		s.trigger = make(chan int64, 16)
	})
}

// Run blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	s.ensureChan()
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()

	// Small initial delay so the first sweep doesn't race with app startup.
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}
	s.sweep(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.sweep(ctx)
		case id := <-s.trigger:
			if id == 0 {
				s.sweep(ctx)
			} else {
				s.runOneByID(ctx, id, "manual")
			}
		}
	}
}

// sweep picks every enabled repo whose next_due <= now and runs it.
// Serial inside the sweep; see package doc for rationale.
func (s *Scheduler) sweep(ctx context.Context) {
	// COALESCE so a just-enrolled repo (last_rehearsed_at = 0) is
	// immediately due. Without it a never-run repo waits forever unless
	// someone hits Run now manually.
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id FROM repos
		WHERE enabled = 1
		  AND (COALESCE(last_rehearsed_at, 0) + cadence_hours * 3600) <= ?
	`, time.Now().Unix())
	if err != nil {
		s.Logger.Warn("scheduler sweep", "err", err)
		return
	}
	defer rows.Close()
	var due []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			due = append(due, id)
		}
	}
	for _, id := range due {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.runOneByID(ctx, id, "schedule")
	}
}

// runOneByID loads the repo row, decrypts its password, builds an
// adapter, runs a rehearsal, persists the result, and fires a
// notification (if configured) on non-pass outcomes.
func (s *Scheduler) runOneByID(ctx context.Context, repoID int64, triggeredBy string) {
	var (
		name, kind, url, pwEnc, source string
		sample                         int
	)
	err := s.DB.QueryRowContext(ctx, `
		SELECT name, kind, repo_url, COALESCE(password_enc, ''), source_path, sample_size
		FROM repos WHERE id = ?
	`, repoID).Scan(&name, &kind, &url, &pwEnc, &source, &sample)
	if err != nil {
		s.Logger.Warn("scheduler: load repo", "repo_id", repoID, "err", err)
		return
	}
	if kind != "restic" {
		s.Logger.Warn("scheduler: unsupported kind (v0.1 is restic-only)", "kind", kind, "repo", name)
		return
	}

	mk, err := db.EnsureMasterKey(ctx, s.DB)
	if err != nil {
		s.Logger.Warn("scheduler: master key", "err", err)
		return
	}
	pwBytes, err := db.Decrypt(mk, pwEnc)
	if err != nil {
		s.Logger.Warn("scheduler: decrypt repo password", "repo", name, "err", err)
		return
	}

	adapter, err := restic.NewAdapter(url, string(pwBytes))
	if err != nil {
		s.Logger.Warn("scheduler: restic adapter", "repo", name, "err", err)
		return
	}

	scratch, _ := db.SettingGet(ctx, s.DB, db.KeyScratchDir)
	started := time.Now()
	s.Logger.Info("rehearsal starting", "repo", name, "trigger", triggeredBy, "sample", sample)
	res, err := rehearse.Run(ctx, s.DB, repoID, source, sample, scratch, adapter)
	if err != nil {
		s.Logger.Warn("rehearsal error", "repo", name, "err", err)
		return
	}
	if _, err := rehearse.PersistResult(ctx, s.DB, repoID, started, triggeredBy, res); err != nil {
		s.Logger.Warn("rehearsal persist", "repo", name, "err", err)
		return
	}
	s.Logger.Info("rehearsal finished",
		"repo", name, "status", res.Status,
		"matched", res.MatchedCount, "diverged", res.DivergedCount,
		"missing", res.MissingCount, "live_files", res.LiveFileCount,
	)

	s.maybeNotify(ctx, name, res)
}

func (s *Scheduler) maybeNotify(ctx context.Context, repoName string, res *rehearse.Result) {
	if s.Notifier == nil {
		return
	}
	var send bool
	switch res.Status {
	case "fail":
		send = db.SettingGetBool(ctx, s.DB, db.KeyNotifyOnFail, true)
	case "degraded":
		send = db.SettingGetBool(ctx, s.DB, db.KeyNotifyOnDegraded, true)
	case "pass":
		send = db.SettingGetBool(ctx, s.DB, db.KeyNotifyOnPass, false)
	}
	if !send {
		return
	}
	var urls []string
	_ = db.SettingGetJSON(ctx, s.DB, db.KeyAppriseURLs, &urls)
	if len(urls) == 0 {
		return
	}
	title := "RestoreRunner: " + res.Status + " — " + repoName
	body := res.Detail
	if body == "" {
		body = "Rehearsal completed with status " + res.Status
	}
	n := notify.New(urls, s.Logger)
	n.Send(ctx, title, body)
}
