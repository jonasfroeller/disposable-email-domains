package middleware

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterBypassHosts(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	// rps=1 burst=1 to make second request normally fail without bypass.
	h := Chain(final, RateLimiter(1, 1, time.Minute, logger, []string{"42websites.com"}))

	// Two rapid requests against bypass host should both succeed.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://42websites.com/test", nil)
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			allow := rec.Code
			// Unexpected rate limiting
			t.Fatalf("expected bypass host always 200, got %d", allow)
		}
	}

	// Non-bypass host should rate limit second request.
	h2 := Chain(final, RateLimiter(1, 1, time.Minute, logger, []string{"42websites.com"}))
	req1 := httptest.NewRequest(http.MethodGet, "http://other.com/test", nil)
	req1.Header.Set("X-Forwarded-For", "5.6.7.8")
	rec1 := httptest.NewRecorder()
	h2.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected first other.com 200 got %d", rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://other.com/test", nil)
	req2.Header.Set("X-Forwarded-For", "5.6.7.8")
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second other.com 429 got %d", rec2.Code)
	}
}
