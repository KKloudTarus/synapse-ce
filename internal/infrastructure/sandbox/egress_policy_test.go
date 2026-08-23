package sandbox

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestResolveEgressPolicyPinsExactDomains(t *testing.T) {
	lookup := func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "api.example.com" {
			t.Fatalf("lookup(%q, %q)", network, host)
		}
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("203.0.113.8"),
			netip.MustParseAddr("203.0.113.7"),
			netip.MustParseAddr("203.0.113.8"),
		}, nil
	}
	resolved, err := resolveEgressPolicy(context.Background(), ports.EgressPolicy{
		AllowDomainRules: []ports.DomainRule{{Host: "API.Example.COM", Ports: []uint16{443}}},
	}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.AllowDomains) != 0 || len(resolved.AllowDomainRules) != 0 {
		t.Fatalf("resolved policy retains domain authority: %+v", resolved)
	}
	wantPins := []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("203.0.113.8")}
	if !slices.Equal(resolved.PinnedHosts["api.example.com"], wantPins) {
		t.Fatalf("pins = %v, want %v", resolved.PinnedHosts, wantPins)
	}
	if len(resolved.Rules) != 2 {
		t.Fatalf("rules = %+v, want two IPv4 rules", resolved.Rules)
	}
	for _, rule := range resolved.Rules {
		if !rule.Allow || !slices.Equal(rule.Ports, []uint16{443}) {
			t.Fatalf("resolved allow rule = %+v", rule)
		}
	}
}

func TestResolveEgressPolicyPreservesDenyPriorityMaterial(t *testing.T) {
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "blocked.example.com" {
			t.Fatalf("host = %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}
	resolved, err := resolveEgressPolicy(context.Background(), ports.EgressPolicy{
		Rules:           []ports.EgressRule{{Allow: true, Net: netip.MustParsePrefix("203.0.113.0/24")}},
		DenyDomainRules: []ports.DomainRule{{Host: "blocked.example.com", Ports: []uint16{8443}}},
	}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Rules) != 2 || resolved.Rules[1].Allow || resolved.Rules[1].Net.String() != "203.0.113.9/32" || !slices.Equal(resolved.Rules[1].Ports, []uint16{8443}) {
		t.Fatalf("resolved rules = %+v", resolved.Rules)
	}
	if len(resolved.PinnedHosts) != 0 {
		t.Fatalf("deny-only host must not enter /etc/hosts: %v", resolved.PinnedHosts)
	}
}

func TestResolveEgressPolicyAddsExistingPinsToKernelRules(t *testing.T) {
	resolved, err := resolveEgressPolicy(context.Background(), ports.EgressPolicy{
		PinnedHosts: map[string][]netip.Addr{"API.Example.COM": {netip.MustParseAddr("203.0.113.7")}},
	}, func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("pre-resolved pins must not trigger DNS")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Rules) != 1 || !resolved.Rules[0].Allow || resolved.Rules[0].Net.String() != "203.0.113.7/32" {
		t.Fatalf("rules = %+v", resolved.Rules)
	}
	if _, ok := resolved.PinnedHosts["api.example.com"]; !ok {
		t.Fatalf("canonical pins = %v", resolved.PinnedHosts)
	}
}

func TestResolveEgressPolicyFailsClosed(t *testing.T) {
	lookupFailure := func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("dns unavailable")
	}
	ipv6Only := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
	}
	for name, test := range map[string]struct {
		policy ports.EgressPolicy
		lookup egressLookup
	}{
		"wildcard":       {policy: ports.EgressPolicy{AllowDomains: []string{"*.example.com"}}, lookup: lookupFailure},
		"lookup failure": {policy: ports.EgressPolicy{AllowDomains: []string{"api.example.com"}}, lookup: lookupFailure},
		"IPv6 only":      {policy: ports.EgressPolicy{AllowDomains: []string{"api.example.com"}}, lookup: ipv6Only},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveEgressPolicy(context.Background(), test.policy, test.lookup); err == nil {
				t.Fatal("unresolvable egress authority must fail closed")
			}
		})
	}
}
