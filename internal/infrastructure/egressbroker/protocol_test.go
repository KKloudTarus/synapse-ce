package egressbroker

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCanonicalPolicyRejectsDomainAuthority(t *testing.T) {
	for _, policy := range []ports.EgressPolicy{
		{AllowDomains: []string{"example.com"}},
		{AllowDomainRules: []ports.DomainRule{{Host: "example.com", Ports: []uint16{443}}}},
		{DenyDomains: []string{"blocked.example"}},
		{PinnedHosts: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("2001:db8::1")}}},
	} {
		if _, err := canonicalPolicy(policy); err == nil {
			t.Fatal("domain-bearing policy must fail closed before reaching the broker")
		}
	}
}

func TestCanonicalPolicyNormalizesRules(t *testing.T) {
	rules, err := canonicalPolicy(ports.EgressPolicy{Rules: []ports.EgressRule{
		{Allow: true, Net: netip.MustParsePrefix("192.0.2.25/24"), Ports: []uint16{443, 80}},
		{Allow: false, Net: netip.MustParsePrefix("198.51.100.0/24")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
	if rules[0].Allow || rules[0].CIDR != "198.51.100.0/24" {
		t.Fatalf("deny-first rule = %+v", rules[0])
	}
	if !rules[1].Allow || rules[1].CIDR != "192.0.2.0/24" || len(rules[1].Ports) != 2 || rules[1].Ports[0] != 80 || rules[1].Ports[1] != 443 {
		t.Fatalf("canonical allow rule = %+v", rules[1])
	}
}

func TestDecodeRequestRejectsProtocolConfusion(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown field":     `{"version":1,"action":"cleanup","run_id":"syn1","command":"rm -rf /"}`,
		"invalid run":       `{"version":1,"action":"cleanup","run_id":"../../host"}`,
		"unknown action":    `{"version":1,"action":"exec","run_id":"syn1"}`,
		"noncanonical cidr": `{"version":1,"action":"setup","run_id":"syn1","slot":1,"rules":[{"allow":true,"cidr":"192.0.2.25/24"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequest(strings.NewReader(raw)); err == nil {
				t.Fatal("malformed request must be rejected")
			}
		})
	}
}

func TestRequestRoundTrip(t *testing.T) {
	want := request{
		Version: protocolVersion, Action: "setup", RunID: "syn7", Slot: 7, PID: 1234,
		TenantID: "tenant-test", ExecutionKind: "recon", ExecutionID: "job-7", Grant: "payload.signature",
		Rules: []CanonicalRule{{Allow: true, CIDR: "203.0.113.0/24", Ports: []uint16{443}}},
	}
	var data bytes.Buffer
	if err := encodeRequest(&data, want); err != nil {
		t.Fatal(err)
	}
	got, err := decodeRequest(&data)
	if err != nil {
		t.Fatal(err)
	}
	if got.RunID != want.RunID || got.Action != want.Action || got.Slot != want.Slot || got.PID != want.PID || got.TenantID != want.TenantID || got.ExecutionKind != want.ExecutionKind || got.ExecutionID != want.ExecutionID || got.Grant != want.Grant || len(got.Rules) != 1 || got.Rules[0].CIDR != want.Rules[0].CIDR {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}
