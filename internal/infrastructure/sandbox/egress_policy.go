package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type egressLookup func(context.Context, string, string) ([]netip.Addr, error)

// resolveEgressPolicy resolves every exact domain once before Bubblewrap starts. The
// resulting addresses are used both for kernel rules and the sandbox's pinned hosts
// file, so the child has no DNS egress and cannot observe a different answer.
// ResolveEgressPolicy resolves and pins every exact domain through the system
// resolver. Control-plane grant issuance uses the same deterministic contract as
// the worker, then independently compares the resulting canonical rules.
func ResolveEgressPolicy(ctx context.Context, policy ports.EgressPolicy) (ports.EgressPolicy, error) {
	return resolveEgressPolicy(ctx, policy, net.DefaultResolver.LookupNetIP)
}

func resolveEgressPolicy(ctx context.Context, policy ports.EgressPolicy, lookup egressLookup) (ports.EgressPolicy, error) {
	if lookup == nil {
		return ports.EgressPolicy{}, errors.New("egress domain resolver is required")
	}
	resolved := ports.EgressPolicy{
		Rules:       cloneEgressRules(policy.Rules),
		PinnedHosts: make(map[string][]netip.Addr, len(policy.PinnedHosts)),
	}
	for rawHost, addrs := range policy.PinnedHosts {
		host, err := exactEgressHost(rawHost)
		if err != nil {
			return ports.EgressPolicy{}, err
		}
		for _, addr := range addrs {
			addr = addr.Unmap()
			if !addr.IsValid() || !addr.Is4() {
				return ports.EgressPolicy{}, fmt.Errorf("pinned host %q contains a non-IPv4 address", host)
			}
			resolved.PinnedHosts[host] = append(resolved.PinnedHosts[host], addr)
			resolved.Rules = append(resolved.Rules, ports.EgressRule{Allow: true, Net: netip.PrefixFrom(addr, 32)})
		}
	}
	for _, domain := range domainRules(policy.AllowDomains, policy.AllowDomainRules) {
		host, addrs, err := resolveEgressDomain(ctx, domain.Host, lookup)
		if err != nil {
			return ports.EgressPolicy{}, fmt.Errorf("resolve allowed egress domain: %w", err)
		}
		resolved.PinnedHosts[host] = append(resolved.PinnedHosts[host], addrs...)
		for _, addr := range addrs {
			resolved.Rules = append(resolved.Rules, ports.EgressRule{
				Allow: true,
				Net:   netip.PrefixFrom(addr, 32),
				Ports: append([]uint16(nil), domain.Ports...),
			})
		}
	}
	for _, domain := range domainRules(policy.DenyDomains, policy.DenyDomainRules) {
		_, addrs, err := resolveEgressDomain(ctx, domain.Host, lookup)
		if err != nil {
			return ports.EgressPolicy{}, fmt.Errorf("resolve denied egress domain: %w", err)
		}
		for _, addr := range addrs {
			resolved.Rules = append(resolved.Rules, ports.EgressRule{
				Allow: false,
				Net:   netip.PrefixFrom(addr, 32),
				Ports: append([]uint16(nil), domain.Ports...),
			})
		}
	}
	resolved.Rules = uniqueEgressRules(resolved.Rules)
	for host, addrs := range resolved.PinnedHosts {
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		resolved.PinnedHosts[host] = slices.Compact(addrs)
	}
	if len(resolved.PinnedHosts) == 0 {
		resolved.PinnedHosts = nil
	}
	return resolved, nil
}

func resolveEgressDomain(ctx context.Context, rawHost string, lookup egressLookup) (string, []netip.Addr, error) {
	host, err := exactEgressHost(rawHost)
	if err != nil {
		return "", nil, err
	}
	addrs, err := lookup(ctx, "ip", host)
	if err != nil {
		return "", nil, fmt.Errorf("lookup %q: %w", host, err)
	}
	ipv4 := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		if addr.IsValid() && addr.Is4() {
			ipv4 = append(ipv4, addr)
		}
	}
	slices.SortFunc(ipv4, func(a, b netip.Addr) int { return a.Compare(b) })
	ipv4 = slices.Compact(ipv4)
	if len(ipv4) == 0 {
		return "", nil, fmt.Errorf("lookup %q returned no IPv4 addresses", host)
	}
	return host, ipv4, nil
}

func exactEgressHost(raw string) (string, error) {
	host, err := engagement.NormalizeDomainPattern(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid egress domain %q: %w", raw, err)
	}
	if strings.Contains(host, "*") {
		return "", fmt.Errorf("wildcard egress domain %q cannot be pinned", host)
	}
	return strings.ToLower(host), nil
}

func domainRules(domains []string, structured []ports.DomainRule) []ports.DomainRule {
	out := make([]ports.DomainRule, 0, len(domains)+len(structured))
	for _, host := range domains {
		out = append(out, ports.DomainRule{Host: host})
	}
	return append(out, structured...)
}

func cloneEgressRules(rules []ports.EgressRule) []ports.EgressRule {
	out := make([]ports.EgressRule, len(rules))
	for i, rule := range rules {
		out[i] = rule
		out[i].Ports = append([]uint16(nil), rule.Ports...)
	}
	return out
}

func uniqueEgressRules(rules []ports.EgressRule) []ports.EgressRule {
	seen := make(map[string]struct{}, len(rules))
	out := make([]ports.EgressRule, 0, len(rules))
	for _, rule := range rules {
		portsCopy := append([]uint16(nil), rule.Ports...)
		sort.Slice(portsCopy, func(i, j int) bool { return portsCopy[i] < portsCopy[j] })
		portsCopy = slices.Compact(portsCopy)
		rule.Ports = portsCopy
		key := fmt.Sprintf("%t|%s|%v", rule.Allow, rule.Net.Masked(), rule.Ports)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rule)
	}
	return out
}
