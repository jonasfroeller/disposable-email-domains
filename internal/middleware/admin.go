package middleware

import (
	"crypto/subtle"
	"log"
	"net/http"
)

// AdminGuard returns a middleware that enforces that all non-GET requests carry
// the correct admin token in header X-Admin-Token. If token is empty, the
// server operates in read-only mode and all non-GET requests are rejected.
//
// Responses:
//
//	401 when header missing (token configured)
//	403 when header present but invalid, or when token not configured (read-only)
func AdminGuard(adminToken string, logger *log.Logger) Middleware {
	tokenBytes := []byte(adminToken)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions { // treat safe methods as public
				next.ServeHTTP(w, r)
				return
			}

			// Read-only mode if no token configured
			if len(tokenBytes) == 0 {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"read-only mode: admin token not configured"}`))
				return
			}

			supplied := r.Header.Get("X-Admin-Token")
			if supplied == "" {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"missing admin token"}`))
				return
			}
			if subtle.ConstantTimeCompare([]byte(supplied), tokenBytes) != 1 {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"invalid admin token"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
