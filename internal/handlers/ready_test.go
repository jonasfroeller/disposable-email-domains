package handlers

import (
	"disposable-email-domains/internal/domain"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestReadyHandler(t *testing.T) {
	// Prepare minimal list + psl file
	_ = os.WriteFile("allowlist.conf", []byte("a.com\n"), 0o644)
	_ = os.WriteFile("blocklist.conf", []byte("b.com\n"), 0o644)
	_ = os.WriteFile("public_suffix_list.dat", []byte("com\n"), 0o644)
	chk := domain.NewChecker("allowlist.conf", "blocklist.conf")
	if err := chk.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	api := &API{Check: chk, Logger: log.New(os.Stdout, "test", 0)}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	api.Ready(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if b := rr.Body.String(); !strings.Contains(b, "\"ready\":true") {
		t.Fatalf("unexpected body: %s", b)
	}
}
