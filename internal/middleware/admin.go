package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"log"
	"math/big"
	"net/http"
	"time"

	"disposable-email-domains/internal/metrics"
	"encoding/json"
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
				writeAuthError(w, http.StatusForbidden, "read_only", "read-only mode: admin token not configured")
				return
			}

			supplied := r.Header.Get("X-Admin-Token")
			if supplied == "" {
				metrics.AdminAuthFailuresTotal.Inc()
				sleepAuth()
				writeAuthError(w, http.StatusUnauthorized, "missing_token", "missing admin token")
				return
			}
			if subtle.ConstantTimeCompare([]byte(supplied), tokenBytes) != 1 {
				metrics.AdminAuthFailuresTotal.Inc()
				sleepAuth()
				writeAuthError(w, http.StatusForbidden, "invalid_token", "invalid admin token")
				return
			}
			metrics.AdminAuthSuccessTotal.Inc()
			next.ServeHTTP(w, r)
		})
	}
}

// AdminGuardMulti extends AdminGuard to support multiple rotating tokens. If the slice is
// empty, the server operates in read-only mode blocking mutating methods. Comparison is
// constant-time per candidate; early exit upon first match.
func AdminGuardMulti(tokens []string, logger *log.Logger) Middleware {
	// Pre-materialize byte slices for constant-time compare
	var tokenBytes [][]byte
	for _, t := range tokens {
		if t == "" { // skip empties defensively
			continue
		}
		tokenBytes = append(tokenBytes, []byte(t))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions { // safe methods
				next.ServeHTTP(w, r)
				return
			}
			if len(tokenBytes) == 0 { // read-only
				writeAuthError(w, http.StatusForbidden, "read_only", "read-only mode: admin token not configured")
				return
			}
			supplied := r.Header.Get("X-Admin-Token")
			if supplied == "" {
				metrics.AdminAuthFailuresTotal.Inc()
				sleepAuth()
				writeAuthError(w, http.StatusUnauthorized, "missing_token", "missing admin token")
				return
			}
			sb := []byte(supplied)
			ok := false
			for _, tb := range tokenBytes {
				if subtle.ConstantTimeCompare(sb, tb) == 1 {
					ok = true
					break
				}
			}
			if !ok {
				metrics.AdminAuthFailuresTotal.Inc()
				sleepAuth()
				writeAuthError(w, http.StatusForbidden, "invalid_token", "invalid admin token")
				return
			}
			metrics.AdminAuthSuccessTotal.Inc()
			next.ServeHTTP(w, r)
		})
	}
}

// Introduces a small randomized delay (50-150ms) to slow brute-force attempts
// without significantly impacting legitimate traffic (hopefully).
func sleepAuth() {
	low := 50
	high := 150
	// random in [low, high]
	if n, err := rand.Int(rand.Reader, big.NewInt(int64(high-low+1))); err == nil {
		time.Sleep(time.Duration(int(n.Int64())+low) * time.Millisecond)
		return
	}
	time.Sleep(100 * time.Millisecond)
}

// Writes a unified error JSON shape consistent with handlers.
func writeAuthError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	payload := map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	}
	_ = json.NewEncoder(w).Encode(payload)
}
