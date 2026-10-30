package dastprobe

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestPublicAddressExcludesSharedSpace(t *testing.T) {
	for _, raw := range []string{"100.64.0.0", "100.100.100.200", "100.127.255.255", "::ffff:100.100.100.200"} {
		if PublicAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("shared address accepted as public: %s", raw)
		}
	}
	for _, raw := range []string{"100.63.255.255", "100.128.0.0", "185.199.108.133", "2606:50c0:8000::154"} {
		if !PublicAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("public address rejected: %s", raw)
		}
	}
}

func TestRunIdentityNeverSerializesOrChangesApproval(t *testing.T) {
	p := Probe{JudgmentID: "j", URL: "https://example.com", Method: "get", RunID: "runtime-only"}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "runtime-only") || strings.Contains(string(encoded), "RunID") {
		t.Fatalf("runtime identity serialized: %s", encoded)
	}
	var decoded Probe
	if err := json.Unmarshal([]byte(`{"RunID":"attacker","URL":"https://example.com"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RunID != "" {
		t.Fatal("request populated runtime identity")
	}
	original := p.ApprovalDigest()
	p.RunID = "different"
	p.Method = " GET "
	if original != p.ApprovalDigest() {
		t.Fatal("runtime identity or equivalent method changed approval")
	}
}
