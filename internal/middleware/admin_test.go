package middleware

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminGuardReadOnly(t *testing.T) {
	mw := AdminGuard("", log.New(testDiscard{}, "", 0))
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("should not reach handler") }))
	req := httptest.NewRequest(http.MethodPost, "/blocklist", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAdminGuardValid(t *testing.T) {
	mw := AdminGuard("secret", log.New(testDiscard{}, "", 0))
	hit := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	req := httptest.NewRequest(http.MethodDelete, "/blocklist", nil)
	req.Header.Set("X-Admin-Token", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !hit {
		t.Fatalf("expected handler to be reached")
	}
}

func TestAdminGuardInvalid(t *testing.T) {
	mw := AdminGuard("secret", log.New(testDiscard{}, "", 0))
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("should not reach handler") }))
	req := httptest.NewRequest(http.MethodPatch, "/blocklist", nil)
	req.Header.Set("X-Admin-Token", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

type testDiscard struct{}

func (testDiscard) Write(p []byte) (int, error) { return len(p), nil }
