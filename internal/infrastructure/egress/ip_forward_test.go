//go:build linux

package egress

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// Egress enforcement must not report itself usable when the kernel will not forward.
//
// Setup builds the namespace, the veth, the MASQUERADE rule and the FORWARD accepts whether or not
// net.ipv4.ip_forward is on, because none of them need it. With it off the kernel drops every
// packet crossing the veth, so a destination the policy allows is as unreachable as one it denies.
// That is the worst shape for a safety control to fail in: it looks configured and correct while
// nothing in scope can be reached, and the tool blames the destination.
//
// This is what made two integration tests look like a hang: every probe was blocked, including the
// one the policy allowed.
func TestProbeRefusesWhenIPForwardingIsOff(t *testing.T) {
	raw, err := os.ReadFile(ipForwardSysctl)
	if err != nil {
		t.Skipf("no %s on this kernel: %v", ipForwardSysctl, err)
	}
	on := strings.TrimSpace(string(raw)) != "0"

	checkErr := checkIPForwarding()
	if on {
		if checkErr != nil {
			t.Fatalf("forwarding is on but the check refused: %v", checkErr)
		}
		return
	}
	if checkErr == nil {
		t.Fatal("forwarding is off but the check passed, so egress would report itself usable")
	}
	if !errors.Is(checkErr, ErrUnavailable) {
		t.Fatalf("error = %v, want it to report egress unavailable", checkErr)
	}
	if !strings.Contains(checkErr.Error(), "ip_forward") {
		t.Fatalf("error = %v, want it to name the sysctl an operator has to set", checkErr)
	}
}
