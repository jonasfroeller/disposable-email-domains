package pslrefresher

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testValidate(data []byte) error { return validate(data) }

func validPSLStub() string {
	// produce >200k bytes and >5000 lines
	body := &strings.Builder{}
	body.WriteString("// ===BEGIN ICANN DOMAINS===\n")
	body.WriteString("com\nnet\norg\n")
	body.WriteString("// ===END ICANN DOMAINS===\n")
	// Each line 60 chars * 4000 lines ~ 240k
	line := strings.Repeat("x", 60) + "\n"
	for i := 0; i < 6000; i++ {
		body.WriteString(line)
	}
	return body.String()
}

func TestValidateSuccess(t *testing.T) {
	if err := testValidate([]byte(validPSLStub())); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestValidateFailures(t *testing.T) {
	// padLarge returns >200k bytes when n is large (61 bytes per line)
	padLarge := func(n int) string { return strings.Repeat(strings.Repeat("x", 60)+"\n", n) }
	cases := []struct{ name, data, wantSub string }{
		{"too-small", "// ===BEGIN ICANN DOMAINS===\n// ===END ICANN DOMAINS===\n", "unexpected size"},
		{"missing-begin", "com\nnet\n// ===END ICANN DOMAINS===\n" + padLarge(6000), "missing ICANN begin"},
		{"missing-end", "// ===BEGIN ICANN DOMAINS===\ncom\n" + padLarge(6000), "missing ICANN end"},
		{"html", "<html>oops</html>\n" + padLarge(4000), "looks like html"},
	}
	for _, c := range cases {
		if err := testValidate([]byte(c.data)); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.wantSub)) {
			t.Fatalf("%s: expected error containing %q got %v", c.name, c.wantSub, err)
		}
	}
}

func TestRefreshNowWithServer(t *testing.T) {
	body := validPSLStub()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256([]byte(body))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("ETag", "\"test-etag-"+hex.EncodeToString(sum[:4])+"\"")
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	dir := t.TempDir()
	dest := filepath.Join(dir, "public_suffix_list.dat")
	logger := log.New(os.Stdout, "test", 0)
	r := New(logger, dest)
	r.URL = srv.URL
	if ok := r.RefreshNow(); !ok {
		t.Fatalf("expected refresh success")
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("expected data written")
	}
}
