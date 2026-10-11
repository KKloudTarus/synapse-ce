package selfhosted

import (
	"net/netip"
	"testing"
)

func TestParsePrivateCIDRsAcceptsPrivateUseRanges(t *testing.T) {
	prefixes, err := ParsePrivateCIDRs([]string{"10.20.0.0/16", " 172.16.5.0/24 ", "192.168.1.7/24", "fd12:3456::/48", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.20.0.0/16", "172.16.5.0/24", "192.168.1.0/24", "fd12:3456::/48", "10.0.0.0/8"}
	for i, prefix := range prefixes {
		if prefix != netip.MustParsePrefix(want[i]) {
			t.Errorf("prefix %d = %s, want %s (masked)", i, prefix, want[i])
		}
	}
}

func TestParsePrivateCIDRsRejectsNonPrivateRanges(t *testing.T) {
	for _, value := range []string{
		"10.0.0.0/7",          // wider than 10.0.0.0/8
		"0.0.0.0/0",           // everything
		"127.0.0.0/8",         // loopback
		"169.254.0.0/16",      // link local and metadata
		"100.64.0.0/10",       // CGNAT
		"8.8.8.0/24",          // public
		"::1/128",             // loopback
		"fe80::/10",           // link local
		"::ffff:10.0.0.0/104", // IPv4-mapped form
		"10.20.0.0",           // not a CIDR
		"not-a-cidr",
	} {
		if _, err := ParsePrivateCIDRs([]string{value}); err == nil {
			t.Errorf("CIDR %q was accepted", value)
		}
	}
}
