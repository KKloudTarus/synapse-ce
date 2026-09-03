package safehttp

import (
	"net/netip"
	"testing"
)

func TestBlockedAddresses(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "100.64.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254"} {
		if !blocked(netip.MustParseAddr(value), true) {
			t.Fatalf("always-blocked address accepted: %s", value)
		}
	}
	for _, value := range []string{"10.0.0.1", "::ffff:10.0.0.1"} {
		if !blocked(netip.MustParseAddr(value), false) {
			t.Fatalf("private address accepted without internal-mirror approval: %s", value)
		}
		if blocked(netip.MustParseAddr(value), true) {
			t.Fatalf("approved internal mirror private address rejected: %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "::ffff:8.8.8.8"} {
		if blocked(netip.MustParseAddr(value), false) {
			t.Fatalf("public address rejected: %s", value)
		}
	}
}
