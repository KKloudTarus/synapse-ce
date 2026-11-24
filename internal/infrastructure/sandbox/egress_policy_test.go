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
			netip.MustParseAddr("93.184.216.38"),
			netip.MustParseAddr("93.184.216.37"),
			netip.MustParseAddr("93.184.216.38"),
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
	wantPins := []netip.Addr{netip.MustParseAddr("93.184.216.37"), netip.MustParseAddr("93.184.216.38")}
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
		PinnedHosts: map[string][]netip.Addr{"API.Example.COM": {netip.MustParseAddr("93.184.216.37")}},
	}, func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("pre-resolved pins must not trigger DNS")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Rules) != 1 || !resolved.Rules[0].Allow || resolved.Rules[0].Net.String() != "93.184.216.37/32" {
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

// The policy's domains are resolved here, separately from every earlier check: acquire resolves a
// host twice before this third lookup, and a DNS answer the other side controls can differ on each
// one. Without a floor, the answer this lookup happens to get is written straight into the kernel
// as an ALLOW rule, so a rebinding host reaches loopback or a metadata endpoint from inside the
// sandbox. Every one of these addresses used to become such a rule.
func TestResolveEgressPolicyRefusesSpecialPurposeAllowAddresses(t *testing.T) {
	for name, addr := range map[string]string{
		"link-local metadata": "169.254.169.254",
		"cgnat metadata":      "100.100.100.200",
		"benchmarking":        "198.18.0.1",
		"protocol assignment": "192.0.0.1",
		"reserved":            "240.0.0.1",
		"documentation":       "203.0.113.4",
		"unspecified":         "0.0.0.0",
	} {
		t.Run(name, func(t *testing.T) {
			lookup := func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(addr)}, nil
			}
			if _, err := resolveEgressPolicy(context.Background(), ports.EgressPolicy{
				AllowDomains: []string{"api.example.com"},
			}, lookup); err == nil {
				t.Errorf("an allow domain resolving to %s must be refused", addr)
			}
			// A pre-resolved pin reaches the kernel without any lookup at all, so it needs the
			// same floor rather than trusting whoever produced it.
			if _, err := resolveEgressPolicy(context.Background(), ports.EgressPolicy{
				PinnedHosts: map[string][]netip.Addr{"api.example.com": {netip.MustParseAddr(addr)}},
			}, func(context.Context, string, string) ([]netip.Addr, error) {
				t.Fatal("a pre-resolved pin must not trigger DNS")
				return nil, nil
			}); err == nil {
				t.Errorf("a pinned host at %s must be refused", addr)
			}
		})
	}
}

// Scanning an internal network is a legitimate deployment, so private-use space stays admitted.
// Only the ranges no egress policy means to open are refused.
// Loopback is admitted on purpose: these rules apply inside the sandbox's own network namespace,
// where 127.0.0.1 is the sandbox's loopback, so refusing it isolates nothing and breaks the
// broker canonicalizer, which resolves "localhost".
func TestResolveEgressPolicyStillAdmitsPrivateAddresses(t *testing.T) {
	for _, addr := range []string{"10.1.2.3", "172.16.4.5", "192.168.0.9", "127.0.0.1"} {
		lookup := func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(addr)}, nil
		}
		resolved, err := resolveEgressPolicy(context.Background(), ports.EgressPolicy{
			AllowDomains: []string{"registry.internal"},
		}, lookup)
		if err != nil {
			t.Fatalf("%s must stay admitted, got %v", addr, err)
		}
		if len(resolved.Rules) != 1 || resolved.Rules[0].Net.Addr().String() != addr {
			t.Fatalf("%s rules = %+v", addr, resolved.Rules)
		}
	}
}

// A DENY rule for an internal address is already implied by the namespace's default drop, and
// filtering one could only widen what gets through. The floor is an allow-path rule only.
func TestResolveEgressPolicyLeavesDenyAddressesAlone(t *testing.T) {
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	resolved, err := resolveEgressPolicy(context.Background(), ports.EgressPolicy{
		DenyDomains: []string{"metadata.internal"},
	}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Rules) != 1 || resolved.Rules[0].Allow || resolved.Rules[0].Net.String() != "169.254.169.254/32" {
		t.Fatalf("deny rules = %+v", resolved.Rules)
	}
}
