package egressbroker

import (
	"context"
	"net/netip"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestEgressGrantCanonicalizerUsesBrokerCanonicalContract(t *testing.T) {
	rules, err := (EgressGrantCanonicalizer{}).Canonicalize(context.Background(), ports.EgressPolicy{Rules: []ports.EgressRule{
		{Allow: true, Net: netip.MustParsePrefix("203.0.113.0/24"), Ports: []uint16{443}},
		{Allow: false, Net: netip.MustParsePrefix("198.51.100.0/24")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Allow || rules[0].CIDR != "198.51.100.0/24" || !rules[1].Allow || rules[1].CIDR != "203.0.113.0/24" {
		t.Fatalf("canonical rules = %+v", rules)
	}
}

func TestEgressGrantCanonicalizerPreservesDomainPortLimits(t *testing.T) {
	rules, err := (EgressGrantCanonicalizer{}).Canonicalize(context.Background(), ports.EgressPolicy{
		AllowDomainRules: []ports.DomainRule{{Host: "localhost", Ports: []uint16{443}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("domain resolved without a kernel allow rule")
	}
	for _, rule := range rules {
		if !rule.Allow || len(rule.Ports) != 1 || rule.Ports[0] != 443 {
			t.Fatalf("HTTPS domain permission widened: %+v", rule)
		}
	}
}
