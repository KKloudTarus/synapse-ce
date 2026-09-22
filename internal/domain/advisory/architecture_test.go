package advisory

import (
	"encoding/json"
	"testing"
)

// TestArchitectureAppliesFailsClosedInBothDirections is the direct unit test for the architecture
// gate. Both failing directions matter and they fail closed for different reasons: an architecture
// outside the vendor's set is positively known not to apply, while an unknown component architecture
// simply cannot be proven to be inside the set. Treating the second as a match is what would let a
// block scoped to "(x86_64)" hit an aarch64 install.
func TestArchitectureAppliesFailsClosedInBothDirections(t *testing.T) {
	for _, current := range []struct {
		name          string
		architectures []string
		component     string
		want          bool
	}{
		{name: "no constraint applies everywhere", architectures: nil, component: "x86_64", want: true},
		{name: "no constraint applies to unknown arch", architectures: nil, component: "", want: true},
		{name: "empty slice is also no constraint", architectures: []string{}, component: "aarch64", want: true},

		{name: "in-set single", architectures: []string{"x86_64"}, component: "x86_64", want: true},
		{name: "in-set multi first", architectures: []string{"aarch64", "ppc64le", "s390x", "x86_64"}, component: "aarch64", want: true},
		{name: "in-set multi last", architectures: []string{"aarch64", "ppc64le", "s390x", "x86_64"}, component: "x86_64", want: true},

		{name: "out-of-set", architectures: []string{"x86_64"}, component: "aarch64", want: false},
		{name: "out-of-set i586", architectures: []string{"aarch64", "ppc64le", "s390x", "x86_64"}, component: "i586", want: false},
		{name: "unknown component arch against constraint", architectures: []string{"x86_64"}, component: "", want: false},
		{name: "blank component arch against constraint", architectures: []string{"x86_64"}, component: "   ", want: false},

		// noarch is a literal architecture token, never a wildcard.
		{name: "noarch matches noarch", architectures: []string{"noarch"}, component: "noarch", want: true},
		{name: "noarch does not match x86_64", architectures: []string{"noarch"}, component: "x86_64", want: false},
		{name: "x86_64 constraint does not match noarch", architectures: []string{"x86_64"}, component: "noarch", want: false},

		// Comparison is case and whitespace insensitive on both sides.
		{name: "case insensitive component", architectures: []string{"x86_64"}, component: "X86_64", want: true},
		{name: "case insensitive constraint", architectures: []string{"X86_64"}, component: "x86_64", want: true},
		{name: "padded component", architectures: []string{"x86_64"}, component: "  x86_64  ", want: true},

		// A constraint that survived normalization as an unmatchable sentinel matches nothing.
		{name: "sentinel matches nothing", architectures: []string{unsatisfiableArchitecture}, component: "x86_64", want: false},
		{name: "sentinel matches not even itself by accident", architectures: []string{unsatisfiableArchitecture}, component: "", want: false},
	} {
		t.Run(current.name, func(t *testing.T) {
			if got := ArchitectureApplies(current.architectures, current.component); got != current.want {
				t.Fatalf("ArchitectureApplies(%q, %q) = %v, want %v", current.architectures, current.component, got, current.want)
			}
		})
	}
}

// TestNormalizeAffectedKeepsBlankArchitectureConstraintUnmatchable is the over-match guard the merge
// path depends on, and the one with the most dangerous failure mode.
//
// An affected block whose architecture constraint is PRESENT but entirely blank is malformed vendor
// evidence, not an absent constraint. Normalizing it to the empty set would silently reclassify it as
// "applies to every architecture" and widen the match, which is the exact over-match this field exists
// to prevent. Normalization therefore substitutes an unmatchable sentinel instead. This test exists
// because a refactor that dropped the sentinel in favour of the empty set would otherwise widen every
// such block with no test failing.
func TestNormalizeAffectedKeepsBlankArchitectureConstraintUnmatchable(t *testing.T) {
	for _, current := range []struct {
		name          string
		architectures []string
	}{
		{name: "single empty token", architectures: []string{""}},
		{name: "whitespace token", architectures: []string{"   "}},
		{name: "tab token", architectures: []string{"\t"}},
		{name: "several blank tokens", architectures: []string{"", "  ", "\t"}},
	} {
		t.Run(current.name, func(t *testing.T) {
			normalized := normalizeAffected(AffectedPackage{
				Ecosystem:     "SUSE:15.6",
				Package:       "libacl1",
				Architectures: current.architectures,
			})
			if len(normalized.Architectures) == 0 {
				t.Fatal("a present-but-blank architecture constraint must NOT normalize to the empty all-architecture set")
			}
			// Nothing real may satisfy it, in either direction.
			for _, component := range []string{"x86_64", "aarch64", "noarch", "i586", ""} {
				if ArchitectureApplies(normalized.Architectures, component) {
					t.Fatalf("malformed constraint must not match component arch %q", component)
				}
			}
		})
	}
}

// TestNormalizeAffectedCanonicalisesRealArchitectures keeps the sentinel behaviour from leaking into
// well-formed evidence: real tokens are lowercased, de-duplicated, and sorted so a block's content
// hash is stable across observations that differ only in vendor letter case or ordering.
func TestNormalizeAffectedCanonicalisesRealArchitectures(t *testing.T) {
	first := normalizeAffected(AffectedPackage{
		Ecosystem:     "SUSE:15.6",
		Package:       "libacl1",
		Architectures: []string{"X86_64", "aarch64", "x86_64", "  PPC64LE  "},
	})
	second := normalizeAffected(AffectedPackage{
		Ecosystem:     "SUSE:15.6",
		Package:       "libacl1",
		Architectures: []string{"ppc64le", "x86_64", "AARCH64"},
	})
	want := []string{"aarch64", "ppc64le", "x86_64"}
	for _, got := range [][]string{first.Architectures, second.Architectures} {
		if len(got) != len(want) {
			t.Fatalf("architectures = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("architectures = %v, want %v", got, want)
			}
		}
	}
	// Equal normalized blocks must serialize identically, which is what keeps the content hash stable.
	a, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("normalized blocks must serialize identically:\n %s\n %s", a, b)
	}
}

// TestAffectedPackageOmitsEmptyArchitectures keeps stored payloads for architecture-blind sources
// byte-identical to their pre-architecture form, so adding the field did not rewrite every existing
// advisory's content hash.
func TestAffectedPackageOmitsEmptyArchitectures(t *testing.T) {
	encoded, err := json.Marshal(AffectedPackage{Ecosystem: "Go", Package: "example.com/mod"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, present := decoded["Architectures"]; present {
		t.Fatalf("an architecture-blind block must omit Architectures entirely, got %s", encoded)
	}
}
