package egress

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// recordingApplier captures every argv this layer would run, without running one.
func recordingApplier() (*Applier, *[]string) {
	var seen []string
	// ip6tables is set so the IPv6 lock-down succeeds; without it setup fails closed before it
	// ever emits an OUTPUT rule, which is the behaviour TestProbeRefuses... already covers.
	a := &Applier{ip: "/sbin/ip", iptables: "/sbin/iptables", ip6tables: "/sbin/ip6tables", netnsDir: "/tmp"}
	a.commandHook = func(_ context.Context, args []string) error {
		seen = append(seen, strings.Join(args, " "))
		return nil
	}
	a.removePinnedNamespace = func(string) error { return nil }
	return a, &seen
}

// Engagement scope normalization accepts any parseable address: `NormalizeTarget` checks that an
// IP parses and nothing else, and `egress.Compile` turns an in-scope target into an ACCEPT rule.
// A tenant admin could therefore put 169.254.169.254 in an engagement and have the kernel accept
// packets to the cloud metadata service from inside the sandbox.
//
// This layer calls itself the structural scope-enforcement backstop, so the floor belongs here:
// iptables matches in order, and these DROPs are emitted before any policy rule, so no later
// ACCEPT can reach them however broad its prefix.
func TestForbiddenDestinationsAreDroppedBeforeAnyAllowRule(t *testing.T) {
	a, seen := recordingApplier()
	// A scope wide enough to cover every forbidden range, which is the case that matters.
	policy := ports.EgressPolicy{Rules: []ports.EgressRule{
		{Allow: true, Net: netip.MustParsePrefix("0.0.0.0/0")},
	}}
	if _, err := a.setup(context.Background(), "floor-test", 0, policy, nil); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Only a destination ACCEPT can race the floor. The namespace also emits
	// "-A OUTPUT -o lo -j ACCEPT", which matches on the output interface: a packet to
	// 169.254.169.254 leaves through the veth, not lo, so that rule never covers it.
	firstAccept := -1
	for i, cmd := range *seen {
		if strings.Contains(cmd, "-A OUTPUT -d ") && strings.Contains(cmd, "-j ACCEPT") {
			firstAccept = i
			break
		}
	}
	if firstAccept < 0 {
		t.Fatal("the sweep recorded no destination ACCEPT rule, so it is not exercising rule emission")
	}
	for _, pfx := range kernelForbiddenDestinations {
		want := "-A OUTPUT -d " + pfx.String() + " -j DROP"
		at := -1
		for i, cmd := range *seen {
			if strings.Contains(cmd, want) {
				at = i
				break
			}
		}
		if at < 0 {
			t.Errorf("%s is never dropped; an allow rule covering it would reach it", pfx)
			continue
		}
		if at > firstAccept {
			t.Errorf("%s is dropped at position %d, after the first ACCEPT at %d; iptables matches in order, so the ACCEPT wins", pfx, at, firstAccept)
		}
	}
}

// 169.254.169.254 and 100.100.100.200 are the two addresses this floor exists for. Holding them by
// value, not only by the prefix that contains them, means a narrowed prefix cannot quietly drop
// them out of the list.
func TestTheMetadataEndpointsAreInsideTheFloor(t *testing.T) {
	for _, raw := range []string{"169.254.169.254", "100.100.100.200", "0.0.0.0", "255.255.255.255"} {
		addr := netip.MustParseAddr(raw)
		covered := false
		for _, pfx := range kernelForbiddenDestinations {
			if pfx.Contains(addr) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("%s is not covered by the kernel floor", raw)
		}
	}
}

// The floor must stay a subset of what every outbound client already refuses, so the two cannot
// drift into disagreeing about a range. The outbound policy admits private-use and loopback here,
// which is what this layer wants too: scanning an internal network is the product, and loopback
// inside the run's own namespace is the tool's own.
func TestKernelFloorIsASubsetOfTheOutboundPolicy(t *testing.T) {
	policy := safehttp.Policy{AllowPrivate: true, AllowLoopback: true}
	for _, pfx := range kernelForbiddenDestinations {
		for _, addr := range []netip.Addr{pfx.Addr(), lastAddrOf(pfx)} {
			if policy.AllowsAddress(addr) {
				t.Errorf("%s is dropped by the kernel floor but admitted by the outbound policy; the two have drifted", addr)
			}
		}
	}
	// Loopback and private-use space must NOT be in the floor: dropping them would break the
	// tool's own loopback and every internal-network engagement.
	for _, raw := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.9", "172.16.4.5"} {
		addr := netip.MustParseAddr(raw)
		for _, pfx := range kernelForbiddenDestinations {
			if pfx.Contains(addr) {
				t.Errorf("%s must stay reachable but %s drops it", raw, pfx)
			}
		}
	}
}

func lastAddrOf(pfx netip.Prefix) netip.Addr {
	addr := pfx.Addr().As4()
	host := uint32(32 - pfx.Bits())
	mask := uint32(1)<<host - 1
	value := uint32(addr[0])<<24 | uint32(addr[1])<<16 | uint32(addr[2])<<8 | uint32(addr[3])
	value |= mask
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// The scope layer refuses the same ranges this layer drops, and it has to keep its own copy:
// internal/domain/engagement is a domain package, which architecture_test.go limits to the domain
// and the standard library, so it cannot import this one. Two tables that must agree and cannot
// share code are kept in step here, where both are visible.
//
// They are two different answers to the same fact. The scope table decides what an operator may
// name; this one decides what a packet may reach. If they drift, a scope accepts a target the
// kernel will drop, which is the misleading state the scope floor exists to remove.
func TestScopeFloorMatchesTheKernelFloor(t *testing.T) {
	scope := engagement.UnreachableRanges()
	if len(scope) != len(kernelForbiddenDestinations) {
		t.Fatalf("the scope floor has %d ranges and the kernel floor %d; they must be the same set", len(scope), len(kernelForbiddenDestinations))
	}
	inKernel := map[netip.Prefix]bool{}
	for _, pfx := range kernelForbiddenDestinations {
		inKernel[pfx] = true
	}
	for _, r := range scope {
		if !inKernel[r.Prefix] {
			t.Errorf("%s is refused at scope entry but not dropped in the kernel; a scope that somehow carried it would reach it", r.Prefix)
		}
		if strings.TrimSpace(r.Why) == "" {
			t.Errorf("%s is refused with no reason for the operator", r.Prefix)
		}
	}
	inScope := map[netip.Prefix]bool{}
	for _, r := range scope {
		inScope[r.Prefix] = true
	}
	for _, pfx := range kernelForbiddenDestinations {
		if !inScope[pfx] {
			t.Errorf("%s is dropped in the kernel but accepted at scope entry; the scope would claim an authorization the run cannot exercise", pfx)
		}
	}
}
