package domain

import (
	"os"
	"testing"
)

func TestValidateRelaxed(t *testing.T) {
	writeTempList(t, "allowlist_relaxed.conf", []string{"good.com"})
	writeTempList(t, "blocklist_relaxed.conf", []string{"bad.com", "sub.example.com", "deep.sub.example.com"})
	defer os.Remove("allowlist_relaxed.conf")
	defer os.Remove("blocklist_relaxed.conf")

	c := NewChecker("allowlist_relaxed.conf", "blocklist_relaxed.conf")

	err := c.Reload(true)
	if err != nil {
		t.Fatalf("Reload(true) failed: %v", err)
	}

	rep := c.Validate()
	if rep.ErrorsFound {
		t.Errorf("Validate() reported ErrorsFound=true, expected false for third-level domains")
	}

	if len(rep.ThirdLevelInBlock) != 2 {
		t.Errorf("Expected 2 third-level domains in report, got %d", len(rep.ThirdLevelInBlock))
	}
}
