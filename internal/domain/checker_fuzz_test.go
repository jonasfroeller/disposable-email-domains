package domain

import "testing"

// FuzzCheckerCheck exercises the Check method with random inputs to ensure it does not panic.
func FuzzCheckerCheck(f *testing.F) {
	c := NewChecker("../../allowlist.conf", "../../blocklist.conf")
	_ = c.Load() // ignore error; fuzz still useful
	seeds := []string{"test@example.com", "Example.COM", "bad..domain", "a@b", "foo@sub.example.co.uk", "idn_ß@ドメイン.example", "justdomain.org"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_ = c.Check(input) // only care about panics / unexpected crashes
	})
}
