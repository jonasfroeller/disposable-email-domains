package handlers

import "testing"

func TestIsLikelyDomain(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"example.com", true},
		{"sub.example.co.uk", true},
		{"localhost", false},
		{"http://example.com", false},
		{"example.com/path", false},
		{"foo@bar.com", false},
		{"-bad.example", false},
		{"bad-.example", false},
		{"exa mple.com", false},
		{"example", false},
		{"..example.com..", true}, // trims dots
	}
	for _, c := range cases {
		if got := isLikelyDomain(c.in); got != c.ok {
			t.Errorf("isLikelyDomain(%q) = %v, want %v", c.in, got, c.ok)
		}
	}
}
