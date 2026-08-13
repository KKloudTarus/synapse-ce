package safehttp

import (
	"net/netip"
	"testing"
)

func TestBlockedAddresses(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "224.0.0.1"} {
		if !blocked(netip.MustParseAddr(value), true) {
			t.Fatalf("always-blocked address accepted: %s", value)
		}
	}
	if !blocked(netip.MustParseAddr("10.0.0.1"), false) {
		t.Fatal("private address accepted without internal-mirror approval")
	}
	if blocked(netip.MustParseAddr("10.0.0.1"), true) {
		t.Fatal("approved internal mirror private address rejected")
	}
	if blocked(netip.MustParseAddr("8.8.8.8"), false) {
		t.Fatal("public address rejected")
	}
}
