package handlers

import (
	"net"
	"testing"
)

func TestIsDisallowedIP(t *testing.T) {
	cases := []struct {
		ip  string
		bad bool
	}{
		{"127.0.0.1", true},             // loopback
		{"10.0.5.7", true},              // private 10/8
		{"172.16.0.1", true},            // private 172.16/12
		{"172.31.255.255", true},        // private upper bound
		{"192.168.1.10", true},          // private 192.168/16
		{"169.254.10.1", true},          // link local
		{"8.8.8.8", false},              // public
		{"1.1.1.1", false},              // public
		{"::1", true},                   // loopback v6
		{"fc00::1", true},               // unique local
		{"fd12:3456:789a::1", true},     // unique local
		{"2001:4860:4860::8888", false}, // public IPv6
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			to := c.ip
			t.Fatalf("failed to parse test ip %s", to)
		}
		if got := isDisallowedIP(ip); got != c.bad {
			if c.bad {
				// if expected bad but not flagged
				t.Errorf("expected disallowed for %s", c.ip)
			} else {
				// expected allowed but flagged
				t.Errorf("unexpected disallow for %s", c.ip)
			}
		}
	}
}
