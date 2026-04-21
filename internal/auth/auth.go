// Package auth owns: admin user bootstrap, password hashing, session
// cookies, and the HTTP middleware that gates every request.
//
// Copied wholesale from patch-pulse and renamed. Docker-socket access in
// RestoreRunner means auth is mandatory — no opt-out.
package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/trstudios/restore-runner/internal/db"
)

// SessionCookieName is the name of the session cookie we set.
const SessionCookieName = "rr_session"

// SessionTTL — how long a session stays valid. Sliding window (extends
// on each request via LastUsedAt).
const SessionTTL = 30 * 24 * time.Hour

// ErrInvalidLogin is returned for wrong-user or wrong-password.
var ErrInvalidLogin = errors.New("invalid username or password")

// User represents a row of the users table.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	MustChange   bool
	CreatedAt    time.Time
}

// AdminExists returns true if there's at least one user row.
func AdminExists(ctx context.Context, d *sql.DB) (bool, error) {
	var count int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count > 0, err
}

// BootstrapAdminFromEnv creates the first admin user from the
// ADMIN_PASSWORD env var if no admin exists yet.
func BootstrapAdminFromEnv(ctx context.Context, d *sql.DB, envUsername, envPassword string) error {
	exists, err := AdminExists(ctx, d)
	if err != nil {
		return fmt.Errorf("check admin: %w", err)
	}
	if exists || envPassword == "" {
		return nil
	}
	username := strings.TrimSpace(envUsername)
	if username == "" {
		username = "admin"
	}
	hashed, err := HashPassword(envPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = d.ExecContext(ctx,
		`INSERT INTO users(username, password_hash, must_change, created_at) VALUES(?, ?, ?, ?)`,
		username, hashed, 1, time.Now().Unix())
	return err
}

// CreateAdmin creates an admin user from the web-UI /setup form.
func CreateAdmin(ctx context.Context, d *sql.DB, username, password string) (*User, error) {
	exists, err := AdminExists(ctx, d)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("admin already exists; use password change instead")
	}
	if strings.TrimSpace(username) == "" || len(password) < 8 {
		return nil, errors.New("username is required and password must be at least 8 characters")
	}
	hashed, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	res, err := d.ExecContext(ctx,
		`INSERT INTO users(username, password_hash, must_change, created_at) VALUES(?, ?, 0, ?)`,
		username, hashed, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Username: username, PasswordHash: hashed, CreatedAt: time.Unix(now, 0)}, nil
}

// HashPassword bcrypts a password for storage.
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// Authenticate validates a username + password, returns the user.
func Authenticate(ctx context.Context, d *sql.DB, username, password string) (*User, error) {
	row := d.QueryRowContext(ctx,
		`SELECT id, username, password_hash, must_change, created_at FROM users WHERE username=?`, username)
	var u User
	var createdUnix int64
	var mustChange int
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &mustChange, &createdUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidLogin
		}
		return nil, err
	}
	u.MustChange = mustChange == 1
	u.CreatedAt = time.Unix(createdUnix, 0)
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidLogin
	}
	return &u, nil
}

// CreateSession issues a new session cookie for the given user.
func CreateSession(ctx context.Context, d *sql.DB, userID int64) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := time.Now()
	_, err = d.ExecContext(ctx,
		`INSERT INTO sessions(token, user_id, created_at, expires_at, last_used_at) VALUES(?,?,?,?,?)`,
		token, userID, now.Unix(), now.Add(SessionTTL).Unix(), now.Unix())
	if err != nil {
		return "", err
	}
	return token, nil
}

// LookupSession returns the user attached to a session token.
func LookupSession(ctx context.Context, d *sql.DB, token string) (*User, error) {
	row := d.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.password_hash, u.must_change, u.created_at, s.expires_at
		FROM sessions s JOIN users u ON s.user_id = u.id
		WHERE s.token = ?
	`, token)
	var u User
	var createdUnix, expiresUnix int64
	var mustChange int
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &mustChange, &createdUnix, &expiresUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, db.ErrNotFound
		}
		return nil, err
	}
	if time.Now().Unix() > expiresUnix {
		_, _ = d.ExecContext(ctx, `DELETE FROM sessions WHERE token=?`, token)
		return nil, db.ErrNotFound
	}
	_, _ = d.ExecContext(ctx,
		`UPDATE sessions SET last_used_at=?, expires_at=? WHERE token=?`,
		time.Now().Unix(), time.Now().Add(SessionTTL).Unix(), token)
	u.MustChange = mustChange == 1
	u.CreatedAt = time.Unix(createdUnix, 0)
	return &u, nil
}

// DeleteSession invalidates a session token (logout).
func DeleteSession(ctx context.Context, d *sql.DB, token string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM sessions WHERE token=?`, token)
	return err
}

// SetSessionCookie writes the cookie on the response with secure defaults.
func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(SessionTTL),
	})
}

// ClearSessionCookie overwrites the cookie with an expired empty one.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
