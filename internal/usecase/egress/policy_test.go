package egress

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func target(kind engagement.TargetKind, v string) engagement.Target {
	return engagement.Target{Kind: kind, Value: v}
}

// findRule returns the first rule whose network equals cidr, or nil.
func findRule(p ports.EgressPolicy, cidr string) *ports.EgressRule {
	want := netip.MustParsePrefix(cidr)
	for i := range p.Rules {
		if p.Rules[i].Net == want {
			return &p.Rules[i]
		}
	}
	return nil
}

func TestCompileCIDRandIP(t *testing.T) {
	p := Compile(engagement.Scope{InScope: []engagement.Target{
		target(engagement.TargetCIDR, "10.0.0.0/24"),
		target(engagement.TargetIP, "203.0.113.5"),
		target(engagement.TargetIP, "2001:db8::1"),
	}})
	if r := findRule(p, "10.0.0.0/24"); r == nil || !r.Allow {
		t.Error("CIDR should compile to an allow rule")
	}
	if r := findRule(p, "203.0.113.5/32"); r == nil || !r.Allow {
		t.Error("IPv4 should compile to a /32 allow")
	}
	if r := findRule(p, "2001:db8::1/128"); r == nil || !r.Allow {
		t.Error("IPv6 should compile to a /128 allow")
	}
}

func TestCompileOutOfScopeWinsOrdering(t *testing.T) {
	p := Compile(engagement.Scope{
		InScope:    []engagement.Target{target(engagement.TargetCIDR, "10.0.0.0/24")},
		OutOfScope: []engagement.Target{target(engagement.TargetIP, "10.0.0.5")},
	})
	// The deny rule must come before any allow rule (out-of-scope wins).
	denyIdx, allowIdx := -1, -1
	for i, r := range p.Rules {
		if !r.Allow && denyIdx < 0 {
			denyIdx = i
		}
		if r.Allow && allowIdx < 0 {
			allowIdx = i
		}
	}
	if denyIdx < 0 || allowIdx < 0 || denyIdx > allowIdx {
		t.Fatalf("deny must precede allow: deny=%d allow=%d rules=%+v", denyIdx, allowIdx, p.Rules)
	}
	if r := findRule(p, "10.0.0.5/32"); r == nil || r.Allow {
		t.Error("the out-of-scope IP must be a deny rule")
	}
}

func TestCompileURLHostPort(t *testing.T) {
	p := Compile(engagement.Scope{InScope: []engagement.Target{
		target(engagement.TargetURL, "https://203.0.113.9:8443/admin"),
		target(engagement.TargetURL, "http://198.51.100.2/"),
	}})
	if r := findRule(p, "203.0.113.9/32"); r == nil || !slices.Contains(r.Ports, 8443) {
		t.Errorf("explicit URL port should be captured: %+v", r)
	}
	if r := findRule(p, "198.51.100.2/32"); r == nil || !slices.Contains(r.Ports, 80) {
		t.Errorf("http default port 80 should be captured: %+v", r)
	}
}

func TestCompileDomainsDeferredToResolution(t *testing.T) {
	p := Compile(engagement.Scope{
		InScope: []engagement.Target{
			target(engagement.TargetDomain, "Example.COM."), // case + trailing dot canonicalized
			target(engagement.TargetURL, "https://app.example.com/x"),
		},
		OutOfScope: []engagement.Target{target(engagement.TargetDomain, "secret.example.com")},
	})
	if !slices.Contains(p.AllowDomains, "example.com") {
		t.Errorf("domain must be canonicalized + deferred for resolution: %v", p.AllowDomains)
	}
	if len(p.AllowDomainRules) != 1 || p.AllowDomainRules[0].Host != "app.example.com" || !slices.Contains(p.AllowDomainRules[0].Ports, 443) {
		t.Errorf("a URL hostname must be deferred with its effective port: %+v", p.AllowDomainRules)
	}
	if !slices.Contains(p.DenyDomains, "secret.example.com") {
		t.Errorf("out-of-scope domain must be a deny-domain: %v", p.DenyDomains)
	}
	// Domains must NOT become a hostname-string rule (only resolved IPs become rules).
	if len(p.Rules) != 0 {
		t.Errorf("domains must not compile to address rules pre-resolution: %+v", p.Rules)
	}
}

func TestCompileURLDomainPreservesEffectivePort(t *testing.T) {
	p := Compile(engagement.Scope{InScope: []engagement.Target{
		target(engagement.TargetURL, "https://API.Example.COM./admin"),
		target(engagement.TargetURL, "http://api.example.com:8080/health"),
	}})
	if got, want := p.AllowDomainRules[0], (ports.DomainRule{Host: "api.example.com", Ports: []uint16{443}}); !slices.Equal(got.Ports, want.Ports) || got.Host != want.Host {
		t.Errorf("first URL rule = %+v, want %+v", got, want)
	}
	if got, want := p.AllowDomainRules[1], (ports.DomainRule{Host: "api.example.com", Ports: []uint16{8080}}); !slices.Equal(got.Ports, want.Ports) || got.Host != want.Host {
		t.Errorf("second URL rule = %+v, want %+v", got, want)
	}
}

func TestCompileOutOfScopeURLDeniesAllPorts(t *testing.T) {
	p := Compile(engagement.Scope{
		InScope: []engagement.Target{
			target(engagement.TargetURL, "https://api.example.com:8443/admin"),
			target(engagement.TargetURL, "https://203.0.113.9:8443/admin"),
		},
		OutOfScope: []engagement.Target{
			target(engagement.TargetURL, "https://api.example.com:443/private"),
			target(engagement.TargetURL, "http://203.0.113.9/private"),
		},
	})
	if len(p.DenyDomainRules) != 1 {
		t.Fatalf("deny URL hostname rules = %+v", p.DenyDomainRules)
	}
	if got := p.DenyDomainRules[0]; got.Host != "api.example.com" || len(got.Ports) != 0 {
		t.Errorf("URL hostname deny must cover all ports: %+v", got)
	}
	if r := findRule(p, "203.0.113.9/32"); r == nil || r.Allow || len(r.Ports) != 0 {
		t.Errorf("URL IP deny must cover all ports: %+v", r)
	}
	if len(p.AllowDomainRules) != 1 || !slices.Equal(p.AllowDomainRules[0].Ports, []uint16{8443}) {
		t.Errorf("URL hostname allow must retain its port: %+v", p.AllowDomainRules)
	}
	allowIP := false
	for _, r := range p.Rules {
		if r.Allow && r.Net == netip.MustParsePrefix("203.0.113.9/32") && slices.Equal(r.Ports, []uint16{8443}) {
			allowIP = true
		}
	}
	if !allowIP {
		t.Errorf("URL IP allow must retain its port: %+v", p.Rules)
	}
}

func TestCompileMalformedNetworkDenyFailsClosed(t *testing.T) {
	p := Compile(engagement.Scope{
		InScope:    []engagement.Target{target(engagement.TargetCIDR, "10.0.0.0/8")},
		OutOfScope: []engagement.Target{target(engagement.TargetURL, "not-a-url")},
	})
	if r := findRule(p, "0.0.0.0/0"); r == nil || r.Allow || len(r.Ports) != 0 {
		t.Errorf("malformed network deny must compile to deny-all: %+v", p.Rules)
	}
}

func TestCompileIgnoresRepoImageAndJunk(t *testing.T) {
	p := Compile(engagement.Scope{InScope: []engagement.Target{
		target(engagement.TargetRepo, "/srv/app"),
		target(engagement.TargetImage, "alpine:3"),
		target(engagement.TargetCIDR, "not-a-cidr"),
		{Kind: engagement.TargetIP, Value: "   "},
	}})
	if len(p.Rules) != 0 || len(p.AllowDomains) != 0 {
		t.Errorf("repo/image/invalid targets must not produce egress rules: %+v", p)
	}
}

func TestCompileMappedIPv6NarrowsToV6Host(t *testing.T) {
	// An IPv4-mapped IPv6 must unmap so it doesn't widen into a v4 match.
	p := Compile(engagement.Scope{InScope: []engagement.Target{
		target(engagement.TargetIP, "::ffff:10.0.0.5"),
	}})
	if findRule(p, "10.0.0.5/32") != nil {
		t.Error("a mapped IPv6 must not compile to a bare v4 /32")
	}
}
