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
	"net/url"
	"strconv"
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
	if v == "" {
		return
	}
	switch t.Kind {
	case engagement.TargetCIDR:
		if pfx, err := netip.ParsePrefix(v); err == nil {
			p.Rules = append(p.Rules, ports.EgressRule{Allow: allow, Net: pfx.Masked()})
		}
	case engagement.TargetIP:
		if a, err := netip.ParseAddr(v); err == nil {
			p.Rules = append(p.Rules, ports.EgressRule{Allow: allow, Net: hostPrefix(a)})
		}
	case engagement.TargetURL:
		host, port := urlHostPort(v)
		if host == "" {
			return
		}
		var portList []uint16
		if port != 0 {
			portList = []uint16{port}
		}
		if a, err := netip.ParseAddr(host); err == nil {
			p.Rules = append(p.Rules, ports.EgressRule{Allow: allow, Net: hostPrefix(a), Ports: portList})
			return
		}
		addDomain(p, allow, host) // a URL with a hostname → resolve at run start
	case engagement.TargetDomain:
		addDomain(p, allow, normalizeHost(v))
	}
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

// hostPrefix returns the single-host prefix for an address (/32 v4, /128 v6). It does
// NOT unmap an IPv4-mapped IPv6 – matching the scope matcher's family-strict stance
// (scope.go addrOf), so a mapped form fails closed (a v6 /128 won't match v4 packets)
// rather than silently widening into a v4 allow.
func hostPrefix(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

// urlHostPort extracts the lowercased host + port from a URL value; port 0 means the
// scheme default (80/443) was implied – callers treat 0 as "the URL's default port".
func urlHostPort(value string) (host string, port uint16) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "://") {
		value = "//" + value // let url.Parse treat a bare host[:port] as the host
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		return "", 0
	}
	host = normalizeHost(u.Hostname())
	if ps := u.Port(); ps != "" {
		if n, err := strconv.Atoi(ps); err == nil && n > 0 && n <= 65535 {
			port = uint16(n)
		}
	} else {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = 443
		case "http":
			port = 80
		}
	}
	return host, port
}

// normalizeHost lowercases + trims a host and strips a single trailing dot (FQDN root),
// so matching is canonical (defeats the trailing-dot / case smuggling class).
func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimSuffix(h, ".")
	return h
}
