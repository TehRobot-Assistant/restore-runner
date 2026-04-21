package auth

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
)

// Routes that are reachable without a valid session. Everything else
// requires login (or redirects to /setup when no admin exists).
var publicPaths = map[string]bool{
	"/login":  true,
	"/setup":  true,
	"/health": true,
}

// Prefix-based public paths — static assets, favicon.
func isPublicPrefix(p string) bool {
	return strings.HasPrefix(p, "/static/") || strings.HasPrefix(p, "/favicon")
}

// contextKey is unexported so no one outside this package can stash a
// value under our key.
type contextKey struct{ name string }

var userKey = &contextKey{"user"}

// UserFromContext returns the authenticated user, or nil if not logged in.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userKey).(*User)
	return u
}

// Middleware gates every request. Behaviour:
//
//   - No admin exists yet → every request redirects to /setup (except
//     /setup itself and /static/*). This matches Jellyfin first-run.
//   - Admin exists but request has no session → redirect to /login
//     unless the path is public.
//   - Session valid → user stashed in context, request continues.
func Middleware(d *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Always allow static assets + truly-public routes (health check,
		// etc). /health must work before admin is configured so Docker
		// healthchecks don't fail during the first-run setup window.
		if isPublicPrefix(r.URL.Path) || publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		exists, err := AdminExists(ctx, d)
		if err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		if !exists {
			// No admin yet — force everything into the setup flow.
			// (Truly public paths already returned above.)
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}

		// Require a valid session for everything else.
		cookie, err := r.Cookie(SessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		user, err := LookupSession(ctx, d, cookie.Value)
		if err != nil {
			ClearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Authenticated — stash user in the request context.
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, userKey, user)))
	})
}
