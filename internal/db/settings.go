package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Settings key constants — single source of truth.
const (
	KeyDefaultCadenceHours = "default_cadence_hours"
	KeyDefaultSampleSize   = "default_sample_size"
	KeyAppriseURLs         = "apprise_urls" // JSON array of strings
	KeyNotifyOnFail        = "notify_on_fail"
	KeyNotifyOnDegraded    = "notify_on_degraded"
	KeyNotifyOnPass        = "notify_on_pass"
	KeyMasterKey           = "master_key_hex" // for encrypting repo passwords at rest
	KeyScratchDir          = "scratch_dir"    // where to restore to during rehearsal
)

// Defaults ship with the app. User can override via Settings UI.
var Defaults = map[string]string{
	KeyDefaultCadenceHours: "168", // weekly
	KeyDefaultSampleSize:   "30",
	KeyAppriseURLs:         "[]",
	KeyNotifyOnFail:        "true",
	KeyNotifyOnDegraded:    "true",
	KeyNotifyOnPass:        "false",
	KeyMasterKey:           "", // generated on first run if empty
	KeyScratchDir:          "/tmp/restorerunner",
}

// SettingGet returns the stored value for a key, or the default if not set.
func SettingGet(ctx context.Context, d *sql.DB, key string) (string, error) {
	var v string
	err := d.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		if def, ok := Defaults[key]; ok {
			return def, nil
		}
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("setting %q: %w", key, err)
	}
	return v, nil
}

func SettingSet(ctx context.Context, d *sql.DB, key, value string) error {
	_, err := d.ExecContext(ctx, `
		INSERT INTO settings(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

func SettingGetJSON(ctx context.Context, d *sql.DB, key string, out any) error {
	v, err := SettingGet(ctx, d, key)
	if err != nil {
		return err
	}
	if v == "" {
		return nil
	}
	return json.Unmarshal([]byte(v), out)
}

func SettingSetJSON(ctx context.Context, d *sql.DB, key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return SettingSet(ctx, d, key, string(b))
}

func SettingGetInt(ctx context.Context, d *sql.DB, key string, fallback int) int {
	v, err := SettingGet(ctx, d, key)
	if err != nil || v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return fallback
	}
	return n
}

func SettingGetBool(ctx context.Context, d *sql.DB, key string, fallback bool) bool {
	v, _ := SettingGet(ctx, d, key)
	switch v {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return fallback
}
