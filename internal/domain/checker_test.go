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
