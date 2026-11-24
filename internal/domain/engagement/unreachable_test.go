package engagement

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// The sandbox drops these ranges in the kernel before it reads the scope, so a scope that accepts
// one claims an authorization the run can never exercise: the operator is told the target is in
// scope and then sees an empty result with nothing explaining it. Refusing at entry makes the
// scope and the kernel agree, and says why.
func TestScopeRefusesAddressesTheSandboxWillNeverReach(t *testing.T) {
	for name, value := range map[string]string{
		"link-local metadata": "169.254.169.254",
		"link-local":          "169.254.1.1",
		"cgnat metadata":      "100.100.100.200",
		"benchmarking":        "198.18.0.1",
		"protocol assignment": "192.0.0.1",
		"reserved":            "240.0.0.1",
		"broadcast":           "255.255.255.255",
		"unspecified":         "0.0.0.0",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NormalizeTarget(Target{Kind: TargetIP, Value: value}, true)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s must be refused, got %v", value, err)
			}
			// The operator has to be able to act on the message, so it names the range and the
			// reason rather than only saying no.
			if got := err.Error(); !strings.Contains(got, value) || !strings.Contains(got, "/") {
				t.Errorf("the refusal must name the address and its range: %q", got)
			}
			// An execution target goes through the same door.
			if _, err := NormalizeTarget(Target{Kind: TargetIP, Value: value}, false); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("%s must be refused as an execution target too, got %v", value, err)
			}
			// A URL whose host is the same literal is the same mistake wearing a scheme.
			if _, err := NormalizeTarget(Target{Kind: TargetURL, Value: "https://" + value + "/"}, true); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("https://%s/ must be refused, got %v", value, err)
			}
		})
	}
}

// Everything an engagement legitimately targets still passes. Private-use space is the important
// one: scanning an internal network is what this product is for.
func TestScopeStillAcceptsEveryLegitimateTarget(t *testing.T) {
	for _, tc := range []struct {
		kind  TargetKind
		value string
	}{
		{TargetIP, "10.1.2.3"},
		{TargetIP, "172.16.4.5"},
		{TargetIP, "192.168.0.9"},
		{TargetIP, "127.0.0.1"},
		{TargetIP, "93.184.216.34"},
		{TargetCIDR, "10.0.0.0/8"},
		{TargetCIDR, "192.168.1.0/24"},
		{TargetCIDR, "93.184.216.0/24"},
		{TargetURL, "https://api.example.com/"},
		{TargetURL, "https://10.1.2.3/"},
		{TargetDomain, "api.example.com"},
	} {
		if _, err := NormalizeTarget(Target{Kind: tc.kind, Value: tc.value}, true); err != nil {
			t.Errorf("%s %q must stay acceptable, got %v", tc.kind, tc.value, err)
		}
	}
}

// A prefix is refused only when every address in it is unreachable. 0.0.0.0/0 is a coarse way of
// saying "anything routable" and the kernel floor carves the unreachable parts out of it, so
// refusing it here would reject a scope that works.
func TestScopeRefusesOnlyWhollyUnreachablePrefixes(t *testing.T) {
	for _, value := range []string{"169.254.0.0/16", "169.254.169.0/24", "100.64.0.0/10", "240.0.0.0/4"} {
		if _, err := NormalizeTarget(Target{Kind: TargetCIDR, Value: value}, true); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s is wholly unreachable and must be refused, got %v", value, err)
		}
	}
	for _, value := range []string{"0.0.0.0/0", "128.0.0.0/1", "10.0.0.0/8"} {
		if _, err := NormalizeTarget(Target{Kind: TargetCIDR, Value: value}, true); err != nil {
			t.Errorf("%s only overlaps an unreachable range and must stay acceptable, got %v", value, err)
		}
	}
}

// The two metadata endpoints are the addresses this floor exists for. Holding them by value means
// narrowing a prefix cannot drop them out of the list quietly.
func TestTheMetadataEndpointsAreCovered(t *testing.T) {
	for _, raw := range []string{"169.254.169.254", "100.100.100.200"} {
		if _, ok := unreachableRange(netip.MustParseAddr(raw)); !ok {
			t.Errorf("%s is not covered", raw)
		}
	}
}

// ::ffff:203.0.113.5 and 203.0.113.5 are the same host, and netip compares them as different:
// neither Contains nor Overlaps crosses the mapping. Before canonicalization that split every
// comparison that reads a scope value. Two consequences, the second much worse than the first:
//
//   - the unreachable floor refused 169.254.169.254 but accepted ::ffff:169.254.169.254/128,
//     so the two spellings disagreed about the same address;
//   - an out-of-scope entry written in the 4-in-6 form matched nothing, so the host an operator
//     had explicitly excluded was authorized and scanned, with no warning anywhere.
//
// NormalizeTarget now unmaps, and every reader of a scope value goes through it.
func TestScopeCanonicalizesIPv4MappedAddresses(t *testing.T) {
	for _, tc := range []struct {
		kind TargetKind
		in   string
		want string
	}{
		{TargetIP, "::ffff:203.0.113.5", "203.0.113.5"},
		{TargetCIDR, "::ffff:203.0.113.0/120", "203.0.113.0/24"},
		{TargetCIDR, "::ffff:203.0.113.5/128", "203.0.113.5/32"},
	} {
		got, err := NormalizeTarget(Target{Kind: tc.kind, Value: tc.in}, true)
		if err != nil {
			t.Fatalf("%s must normalize, got %v", tc.in, err)
		}
		if got.Value != tc.want {
			t.Errorf("%s normalized to %q, want %q; an uncanonical value splits every later comparison", tc.in, got.Value, tc.want)
		}
	}
	// The unreachable floor sees one spelling, so both are refused.
	for _, tc := range []struct {
		kind TargetKind
		in   string
	}{
		{TargetIP, "::ffff:169.254.169.254"},
		{TargetCIDR, "::ffff:169.254.169.254/128"},
		{TargetCIDR, "::ffff:169.254.0.0/112"},
		{TargetURL, "https://[::ffff:169.254.169.254]/"},
	} {
		if _, err := NormalizeTarget(Target{Kind: tc.kind, Value: tc.in}, true); err == nil {
			t.Errorf("%s is the metadata endpoint in another spelling and must be refused", tc.in)
		}
	}
}

// The authorization half, which is what the inconsistency actually cost.
func TestOutOfScopeExcludesTheHostHoweverItIsSpelled(t *testing.T) {
	for name, outOfScope := range map[string]Target{
		"dotted":            {Kind: TargetCIDR, Value: "203.0.113.5/32"},
		"4-in-6":            {Kind: TargetCIDR, Value: "::ffff:203.0.113.5/128"},
		"bare ip in 4-in-6": {Kind: TargetIP, Value: "::ffff:203.0.113.5"},
	} {
		t.Run(name, func(t *testing.T) {
			scope := Scope{
				InScope:    []Target{{Kind: TargetCIDR, Value: "203.0.113.0/24"}},
				OutOfScope: []Target{outOfScope},
			}
			if scope.AllowsTarget(Target{Kind: TargetIP, Value: "203.0.113.5"}) {
				t.Error("an explicitly excluded host must not be authorized, whatever spelling the exclusion used")
			}
			// The exclusion must stay narrow: its neighbour is still in scope.
			if !scope.AllowsTarget(Target{Kind: TargetIP, Value: "203.0.113.9"}) {
				t.Error("the exclusion widened beyond the host it names")
			}
		})
	}
}
