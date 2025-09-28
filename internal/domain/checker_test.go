package domain

import (
	"os"
	"testing"
)

func writeTempList(t *testing.T, path string, lines []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, l := range lines {
		_, _ = f.WriteString(l + "\n")
	}
	_ = f.Close()
}

func TestCheckerLoadAndCheck(t *testing.T) {
	writeTempList(t, "allowlist.conf", []string{"good.com"})
	writeTempList(t, "blocklist.conf", []string{"bad.com"})
	c := NewChecker("allowlist.conf", "blocklist.conf")
	if err := c.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !c.IsReady() {
		t.Fatalf("checker not ready after load")
	}
	r1 := c.Check("user@good.com")
	if r1.Status != "allow" || !r1.Allowlisted {
		t.Fatalf("expected allow, got %+v", r1)
	}
	r2 := c.Check("bad.com")
	if r2.Status != "block" || !r2.Blocklisted {
		t.Fatalf("expected block, got %+v", r2)
	}
	r3 := c.Check("neutral.io")
	if r3.Status != "neutral" {
		t.Fatalf("expected neutral, got %+v", r3)
	}
}

func TestETLD1Matching(t *testing.T) {
	writeTempList(t, "allowlist.conf", []string{"good.com"})
	writeTempList(t, "blocklist.conf", []string{"bad.com"})
	c := NewChecker("allowlist.conf", "blocklist.conf")
	if err := c.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	// Subdomain of allowlisted domain should be allowed
	r1 := c.Check("user@mail.good.com")
	if r1.Status != "allow" || !r1.Allowlisted {
		t.Fatalf("expected allow via eTLD+1, got %+v", r1)
	}
	// Subdomain of blocklisted domain should be blocked
	r2 := c.Check("x.y.bad.com")
	if r2.Status != "block" || !r2.Blocklisted {
		t.Fatalf("expected block via eTLD+1, got %+v", r2)
	}
	// Lookalike domain containing bad.com as a label should NOT match
	r3 := c.Check("bad.com.notbad.org")
	if r3.Status != "neutral" {
		t.Fatalf("expected neutral for lookalike, got %+v", r3)
	}
}
