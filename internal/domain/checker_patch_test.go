package domain

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPatchBlock ensures that PatchBlock updates in-memory structures immediately
// without requiring a full Reload, and that duplicates are ignored.
func TestPatchBlock(t *testing.T) {
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allowlist.conf")
	blockPath := filepath.Join(dir, "blocklist.conf")
	if err := os.WriteFile(allowPath, []byte("foo.com\n"), 0o644); err != nil {
		t.Fatalf("write allow: %v", err)
	}
	if err := os.WriteFile(blockPath, []byte("bar.com\n"), 0o644); err != nil {
		t.Fatalf("write block: %v", err)
	}
	c := NewChecker(allowPath, blockPath)
	if err := c.Load(); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	// Sanity: bar.com should be blocklisted, baz.io not yet.
	res1 := c.Check("baz.io")
	if res1.Blocklisted {
		t.Fatalf("expected baz.io not blocklisted initially")
	}
	// Patch new domains (including duplicate bar.com and comment/empty lines)
	c.PatchBlock([]string{"baz.io", "bar.com", "#comment", "   ", "Quux.Org"})

	res2 := c.Check("baz.io")
	if !res2.Blocklisted {
		t.Fatalf("expected baz.io now blocklisted after PatchBlock")
	}
	res3 := c.Check("quux.org")
	if !res3.Blocklisted {
		t.Fatalf("expected quux.org blocklisted (case-normalized)")
	}
	// Ensure duplicate didn't create multiple raw entries for bar.com by counting occurrences.
	c.mu.RLock()
	countBar := 0
	for _, raw := range c.rawBlock {
		if raw == "bar.com" {
			countBar++
		}
	}
	c.mu.RUnlock()
	if countBar != 1 {
		t.Fatalf("expected single bar.com in rawBlock, got %d", countBar)
	}
}
