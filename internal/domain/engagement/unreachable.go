package engagement

import "net/netip"

// UnreachableRange is one address range a target may never name, with the reason an operator sees.
type UnreachableRange struct {
	Prefix netip.Prefix
	Why    string
}

// unreachableRanges are the destinations the sandbox drops in the kernel before it reads an
// engagement's scope at all (internal/infrastructure/egress, kernelForbiddenDestinations). Naming
// one as a target used to be accepted and then silently dropped, so the scope claimed an
// authorization the run could never exercise. Refusing it here makes the two agree and tells the
// operator why, instead of leaving them to infer it from an empty result.
//
// The list is deliberately the same as the kernel's, and TestScopeFloorMatchesTheKernelFloor in
// internal/infrastructure/egress holds them together. It cannot be shared as code: this is a
// domain package, which internal/platform/architecture_test.go limits to the domain and the
// standard library, so the two tables are kept in step by a test rather than by an import.
//
// Loopback and private-use space are absent for the same reasons they are absent there: inside the
// run's network namespace 127.0.0.1 is the tool's own loopback, and scanning an internal network is
// what this product is for.
var unreachableRanges = []UnreachableRange{
	{netip.MustParsePrefix("0.0.0.0/8"), "this network"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link local, where the cloud metadata service lives"},
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT, which holds the Alibaba and OpenStack metadata service"},
	{netip.MustParsePrefix("192.0.0.0/24"), "IETF protocol assignments"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},
}

// UnreachableRanges returns the ranges a target may never name. It exists so the sandbox layer can
// assert its own kernel floor still matches this one.
func UnreachableRanges() []UnreachableRange {
	out := make([]UnreachableRange, len(unreachableRanges))
	copy(out, unreachableRanges)
	return out
}

// unreachableRange reports the range that swallows addr, if any.
func unreachableRange(addr netip.Addr) (UnreachableRange, bool) {
	addr = addr.Unmap()
	for _, r := range unreachableRanges {
		if r.Prefix.Contains(addr) {
			return r, true
		}
	}
	return UnreachableRange{}, false
}

// unreachablePrefix reports the range that swallows pfx WHOLE. A prefix that merely overlaps one is
// allowed: 0.0.0.0/0 is a coarse way of saying "anything routable", and the kernel floor carves the
// unreachable parts out of it. Only a prefix every address of which is unreachable is a mistake
// worth refusing, because nothing in it can ever answer.
func unreachablePrefix(pfx netip.Prefix) (UnreachableRange, bool) {
	// Belt: NormalizeTarget canonicalizes before calling, but a future caller might not, and a
	// 4-in-6 prefix silently matches no IPv4 range rather than erroring.
	if pfx.Addr().Is4In6() {
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
	}
	for _, r := range unreachableRanges {
		if r.Prefix.Overlaps(pfx) && r.Prefix.Bits() <= pfx.Bits() && r.Prefix.Contains(pfx.Addr()) {
			return r, true
		}
	}
	return UnreachableRange{}, false
}
