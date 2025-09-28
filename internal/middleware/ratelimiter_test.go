package middleware

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func init() {
	// Ensure tests relying on X-Forwarded-For keep working after trust proxy toggle addition.
	SetTrustProxyHeaders(true)
}

func doReq(h http.Handler, ip string) int {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRateLimiterBurstExhaustion(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	// rps=1, burst=1 so only first immediate request allowed.
	h := Chain(final, RateLimiter(1, 1, time.Minute, logger, nil))

	if code := doReq(h, "1.2.3.4"); code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", code)
	}
	if code := doReq(h, "1.2.3.4"); code != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d", code)
	}
	// Different IP should have its own bucket
	if code := doReq(h, "5.6.7.8"); code != http.StatusOK {
		t.Fatalf("expected different IP request 200, got %d", code)
	}
}

func TestRateLimiterBucketEviction(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	ttl := 100 * time.Millisecond
	h := Chain(final, RateLimiter(1, 1, ttl, logger, nil))

	if code := doReq(h, "9.9.9.9"); code != http.StatusOK {
		t.Fatalf("expected initial request 200, got %d", code)
	}
	if code := doReq(h, "9.9.9.9"); code != http.StatusTooManyRequests {
		t.Fatalf("expected immediate second request 429, got %d", code)
	}
	// Wait long enough for eviction goroutine to cull the entry
	time.Sleep(3 * ttl)
	// After eviction, first request should again succeed (fresh limiter)
	if code := doReq(h, "9.9.9.9"); code != http.StatusOK {
		t.Fatalf("expected request after eviction 200, got %d", code)
	}
}
