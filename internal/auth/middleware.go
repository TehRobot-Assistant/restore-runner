package auth

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
)

// Routes that are reachable without a valid session.
var publicPaths = map[string]bool{
	"/login":  true,
	"/setup":  true,
	"/health": true,
}

func isPublicPrefix(p string) bool {
	return strings.HasPrefix(p, "/static/") || strings.HasPrefix(p, "/favicon")
}

type contextKey struct{ name string }

var userKey = &contextKey{"user"}

// UserFromContext returns the authenticated user, or nil if not logged in.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userKey).(*User)
	return u
}

// Middleware gates every request.
func Middleware(d *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

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
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}

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

		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, userKey, user)))
	})
}
