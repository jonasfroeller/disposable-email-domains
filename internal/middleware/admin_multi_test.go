package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminGuardMulti(t *testing.T) {
	valid := []string{"this_is_a_valid_admin_token_123", "another_valid_admin_token_456"}
	mw := AdminGuardMulti(valid, nil)
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	ts := httptest.NewServer(mw(okHandler))
	defer ts.Close()

	// GET should always pass (no token) as safe method
	resp, err := http.Get(ts.URL + "/foo")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 for GET got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// POST without token -> 401
	resp, err = http.Post(ts.URL+"/foo", "application/json", nil)
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 missing token got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// POST with invalid token -> 403
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/foo", nil)
	req.Header.Set("X-Admin-Token", "bad_token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST invalid token error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 invalid token got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// POST with first valid token -> 204
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/foo", nil)
	req2.Header.Set("X-Admin-Token", valid[0])
	resp, err = http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("POST valid token error: %v", err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 valid token got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// POST with second valid token -> 204
	req3, _ := http.NewRequest(http.MethodPost, ts.URL+"/foo", nil)
	req3.Header.Set("X-Admin-Token", valid[1])
	resp, err = http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("POST valid token2 error: %v", err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 valid token2 got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestAdminGuardMultiReadOnly(t *testing.T) {
	// No tokens -> read-only
	mw := AdminGuardMulti(nil, nil)
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	ts := httptest.NewServer(mw(okHandler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/foo")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 for GET got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/foo", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 read-only got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}
