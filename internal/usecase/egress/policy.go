// Package egress compiles an engagement scope into a default-deny egress policy: the
// concrete set of {destination, ports} a sandboxed tool may reach. It is
// the kernel-enforced backstop for scope enforcement – the gate refuses to LAUNCH an
// out-of-scope run; this policy makes the kernel DROP any out-of-scope packet a tool
// tries to send. The compiler is a pure, deterministic function of the scope; the
// netns/iptables application + DNS pinning live in infrastructure. (The
// as-built enforcement uses iptables, not the originally-planned nftables.)
//
// Security stance (the market lesson): the allowlist is defense-in-depth behind the
// sandbox's network namespace, never the boundary. It is matched on RESOLVED addresses
// (CIDRs), not on a tool's hostname string, and out-of-scope wins (deny rules first).
package egress

import (
	"net/netip"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Compile turns an engagement scope into a ports.EgressPolicy. Out-of-scope entries
// become deny rules ordered before the allows (out-of-scope wins). Repo/image targets
// are ignored (not network destinations). The result is deterministic. The rule/policy
// data types live in ports so the infrastructure applier can enforce them without an
// inward-rule violation.
func Compile(scope engagement.Scope) ports.EgressPolicy {
	var p ports.EgressPolicy
	for _, t := range scope.OutOfScope {
		addTarget(&p, false, t)
	}
	for _, t := range scope.InScope {
		addTarget(&p, true, t)
	}
	return p
}

// addTarget compiles one target into a concrete rule (or a pending-domain entry).
func addTarget(p *ports.EgressPolicy, allow bool, t engagement.Target) {
	v := strings.TrimSpace(t.Value)
	if t.Kind == engagement.TargetRepo || t.Kind == engagement.TargetImage {
		return
	}
	if v == "" {
		if !allow {
			addDenyAll(p)
		}
		return
	}
	switch t.Kind {
	case engagement.TargetCIDR:
		if pfx, err := netip.ParsePrefix(v); err == nil {
			p.Rules = append(p.Rules, ports.EgressRule{Allow: allow, Net: pfx.Masked()})
		} else if !allow {
			addDenyAll(p)
		}
	case engagement.TargetIP:
		if a, err := netip.ParseAddr(v); err == nil {
			p.Rules = append(p.Rules, ports.EgressRule{Allow: allow, Net: hostPrefix(a)})
		} else if !allow {
			addDenyAll(p)
		}
	case engagement.TargetURL:
		host, port := urlHostPort(v)
		if host == "" {
			if !allow {
				addDenyAll(p)
			}
			return
		}
		var portList []uint16
		if allow {
			portList = []uint16{port}
		}
		if a, err := netip.ParseAddr(host); err == nil {
			p.Rules = append(p.Rules, ports.EgressRule{Allow: allow, Net: hostPrefix(a), Ports: portList})
			return
		}
		addDomainRule(p, allow, host, portList)
	case engagement.TargetDomain:
		host, err := engagement.NormalizeDomainPattern(v)
		if err != nil {
			if !allow {
				addDenyAll(p)
			}
			return
		}
		addDomain(p, allow, host)
	default:
		if !allow {
			addDenyAll(p)
		}
	}
}

func addDenyAll(p *ports.EgressPolicy) {
	p.Rules = append(p.Rules, ports.EgressRule{
		Allow: false,
		Net:   netip.PrefixFrom(netip.IPv4Unspecified(), 0),
	})
}

func addDomain(p *ports.EgressPolicy, allow bool, host string) {
	if host == "" {
		return
	}
	if allow {
		p.AllowDomains = append(p.AllowDomains, host)
	} else {
		p.DenyDomains = append(p.DenyDomains, host)
	}
}

func addDomainRule(p *ports.EgressPolicy, allow bool, host string, portList []uint16) {
	if host == "" {
		return
	}
	rule := ports.DomainRule{Host: host, Ports: portList}
	if allow {
		p.AllowDomainRules = append(p.AllowDomainRules, rule)
	} else {
		p.DenyDomainRules = append(p.DenyDomainRules, rule)
	}
}

// hostPrefix returns the single-host prefix for an address (/32 v4, /128 v6). It does
// NOT unmap an IPv4-mapped IPv6 – matching the scope matcher's family-strict stance
// (scope.go addrOf), so a mapped form fails closed (a v6 /128 won't match v4 packets)
// rather than silently widening into a v4 allow.
func hostPrefix(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

// urlHostPort extracts the canonical host and effective port from an HTTP(S)
// URL. NormalizeURL expands an omitted port to the scheme default.
func urlHostPort(value string) (host string, port uint16) {
	identity, err := engagement.NormalizeURL(value)
	if err != nil {
		return "", 0
	}
	return identity.Host, identity.Port
}
