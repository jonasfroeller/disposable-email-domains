package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"disposable-email-domains/internal/metrics"

	"golang.org/x/time/rate"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
)

func RequestID(r *http.Request) string {
	if v := r.Context().Value(requestIDKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func RequestIDMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var buf [8]byte
			_, _ = rand.Read(buf[:])
			id := hex.EncodeToString(buf[:])
			ctx := context.WithValue(r.Context(), requestIDKey, id)
			w.Header().Set("X-Request-ID", id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Returns a middleware using x/time/rate with per-IP buckets.
// Buckets expire after ttl of inactivity. rps & burst are configurable.
func RateLimiter(rps float64, burst int, ttl time.Duration, logger *log.Logger, bypassHosts []string) Middleware {
	if rps <= 0 {
		rps = 5
	}
	if burst <= 0 {
		burst = 20
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	type entry struct {
		lim  *rate.Limiter
		last time.Time
	}
	var (
		mu sync.Mutex
		m  = make(map[string]*entry)
	)
	// Background cleanup goroutine (best-effort, non-blocking).
	go func() {
		ticker := time.NewTicker(ttl / 2)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			cut := time.Now().Add(-ttl)
			for k, e := range m {
				if e.last.Before(cut) {
					delete(m, k)
				}
			}
			mu.Unlock()
		}
	}()
	// Build lookup set for O(1) host match (case-insensitive host names normalized to lowercase without port)
	bypass := make(map[string]struct{}, len(bypassHosts))
	for _, h := range bypassHosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		bypass[h] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fast path: bypass if host matches configured domain list.
			host := r.Host
			if i := strings.IndexByte(host, ':'); i != -1 {
				host = host[:i]
			}
			host = strings.ToLower(host)
			if _, ok := bypass[host]; ok {
				next.ServeHTTP(w, r)
				return
			}
			ip := clientIP(r)
			mu.Lock()
			e, ok := m[ip]
			if !ok {
				e = &entry{lim: rate.NewLimiter(rate.Limit(rps), burst), last: time.Now()}
				m[ip] = e
			}
			if !e.lim.Allow() {
				metrics.RateLimitRejectedTotal.Inc()
				mu.Unlock()
				w.Header().Set("Retry-After", "1")
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limited"}`))
				return
			}
			e.last = time.Now()
			mu.Unlock()
			next.ServeHTTP(w, r)
		})
	}
}

type Middleware func(http.Handler) http.Handler

func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

type statusWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	return n, err
}

func Logging(logger *log.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			dur := time.Since(start)
			// record metrics (path uses URL.Path directly; for high-cardinality paths consider normalization later)
			// expose request duration header in milliseconds (integer)
			w.Header().Set("X-Request-Duration-ms", strconv.FormatInt(dur.Milliseconds(), 10))
			metrics.ObserveRequest(r.Method, r.URL.Path, http.StatusText(sw.status), dur, sw.status)
			ua := r.Header.Get("User-Agent")
			ip := clientIP(r)
			reqID := RequestID(r)
			if reqID != "" {
				logger.Printf("%s %s %d %dB %s ip=%s rid=%s ua=%q", r.Method, r.URL.Path, sw.status, sw.size, dur, ip, reqID, ua)
			} else {
				logger.Printf("%s %s %d %dB %s ip=%s ua=%q", r.Method, r.URL.Path, sw.status, sw.size, dur, ip, ua)
			}
		})
	}
}

func Recover(logger *log.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Printf("panic: %v\n%s", rec, debug.Stack())
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func SecurityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
			next.ServeHTTP(w, r)
		})
	}
}

func VersionHeader(ver string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ver != "" {
				w.Header().Set("X-Service-Version", ver)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Redirects GET requests from original "/check" paths to WAF-safe aliases.
//
// Rules:
// - GET /check -> /q (preserve query string)
// - GET /check/emails/... -> /emails/...
// - GET /check/domains/... -> /domains/...
// Only applies when enabled. Other methods pass through unchanged.
func RedirectCheckPaths(enabled bool) Middleware {
	if !enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			p := r.URL.Path
			// Exact /check -> /q
			if p == "/check" {
				target := "/q"
				if r.URL.RawQuery != "" {
					target = target + "?" + r.URL.RawQuery
				}
				// 307 preserves method; suitable for GET/HEAD
				w.Header().Set("Location", target)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			// Prefix rewrites
			if strings.HasPrefix(p, "/check/emails/") {
				target := "/emails/" + strings.TrimPrefix(p, "/check/emails/")
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				w.Header().Set("Location", target)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			if strings.HasPrefix(p, "/check/domains/") {
				target := "/domains/" + strings.TrimPrefix(p, "/check/domains/")
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				w.Header().Set("Location", target)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Whether it should honor X-Forwarded-For / X-Real-IP headers.
// Set once during startup via SetTrustProxyHeaders and read concurrently.
var trustProxy atomic.Bool

// Configures whether clientIP should trust proxy-provided headers.
func SetTrustProxyHeaders(v bool) { trustProxy.Store(v) }

func clientIP(r *http.Request) string {
	if trustProxy.Load() {
		for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
			if v := r.Header.Get(h); v != "" {
				parts := strings.Split(v, ",")
				return strings.TrimSpace(parts[0])
			}
		}
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i != -1 {
		return ip[:i]
	}
	return ip
}
