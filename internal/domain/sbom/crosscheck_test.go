package sbom

import (
	"reflect"
	"testing"
)

func comp(name, version, purl string) Component {
	return Component{Name: name, Version: version, PURL: purl}
}

func doc(source string, comps ...Component) *SBOM {
	return &SBOM{Source: source, Components: comps}
}

func TestCrossCheckAgreement(t *testing.T) {
	c := []Component{comp("left-pad", "1.0.0", "pkg:npm/left-pad@1.0.0"), comp("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")}
	r := CrossCheck([]string{"syft", "ownsbom"}, []*SBOM{doc("syft", c...), doc("ownsbom", c...)})
	if !reflect.DeepEqual(r.Producers, []string{"ownsbom", "syft"}) {
		t.Errorf("producers (sorted, distinct): %v", r.Producers)
	}
	if len(r.Agreed) != 2 || len(r.Disagreements) != 0 {
		t.Fatalf("want 2 agreed, 0 disagreements; got %d/%d", len(r.Agreed), len(r.Disagreements))
	}
}

func TestCrossCheckDisagreement(t *testing.T) {
	// syft finds an extra transitive dep (it has the dep-graph); ownsbom misses it.
	syft := doc("syft", comp("left-pad", "1.0.0", "pkg:npm/left-pad@1.0.0"), comp("ms", "2.1.3", "pkg:npm/ms@2.1.3"))
	owned := doc("ownsbom", comp("left-pad", "1.0.0", "pkg:npm/left-pad@1.0.0"))
	r := CrossCheck([]string{"syft", "ownsbom"}, []*SBOM{syft, owned})
	if len(r.Agreed) != 1 || len(r.Disagreements) != 1 {
		t.Fatalf("want 1 agreed, 1 disagreement; got %d/%d", len(r.Agreed), len(r.Disagreements))
	}
	d := r.Disagreements[0]
	if d.PURL != "pkg:npm/ms@2.1.3" {
		t.Errorf("expected the ms component flagged; got %+v", d)
	}
	if !reflect.DeepEqual(d.Reporters, []string{"syft"}) || !reflect.DeepEqual(d.Missing, []string{"ownsbom"}) {
		t.Errorf("reporters/missing wrong: %+v", d)
	}
}

func TestCrossCheckEmptyProducerStillCounts(t *testing.T) {
	// ownsbom ran but produced an empty SBOM (no recognized manifests) – it must still be Missing on
	// everything syft emitted, never silently dropped (the union-expands invariant).
	r := CrossCheck([]string{"syft", "ownsbom"}, []*SBOM{
		doc("syft", comp("left-pad", "1.0.0", "pkg:npm/left-pad@1.0.0")),
		doc("ownsbom"), // zero components
	})
	if !reflect.DeepEqual(r.Producers, []string{"ownsbom", "syft"}) {
		t.Errorf("an empty producer must still be in the run set: %v", r.Producers)
	}
	if len(r.Disagreements) != 1 || !reflect.DeepEqual(r.Disagreements[0].Missing, []string{"ownsbom"}) {
		t.Errorf("want left-pad missing from ownsbom; got %+v", r.Disagreements)
	}
}

func TestCrossCheckIdentityFallback(t *testing.T) {
	// no PURL → identity is name@version; both producers emit the same one → agreed.
	r := CrossCheck([]string{"syft", "ownsbom"}, []*SBOM{
		doc("syft", comp("acme-lib", "2.0.0", "")),
		doc("ownsbom", comp("acme-lib", "2.0.0", "")),
	})
	if len(r.Agreed) != 1 || len(r.Disagreements) != 0 {
		t.Fatalf("name@version identity should agree; got %d/%d", len(r.Agreed), len(r.Disagreements))
	}
}

func TestCrossCheckNilAndEmpty(t *testing.T) {
	r := CrossCheck(nil, []*SBOM{nil})
	if len(r.Producers) != 0 || len(r.Agreed) != 0 || len(r.Disagreements) != 0 {
		t.Errorf("nil/empty input: want an empty report; got %+v", r)
	}
}

func TestCrossCheckDedupsAndSkipsBlank(t *testing.T) {
	// A producer listing the same component twice counts as ONE reporter (set semantics), and a
	// fully-blank component (empty ComponentID) is dropped – never a phantom item. Pins both invariants.
	c := comp("left-pad", "1.0.0", "pkg:npm/left-pad@1.0.0")
	r := CrossCheck([]string{"syft", "ownsbom"}, []*SBOM{
		doc("syft", c, c, comp("", "", "")), // duplicate + a blank component
		doc("ownsbom", c),
	})
	if len(r.Agreed) != 1 || len(r.Disagreements) != 0 {
		t.Fatalf("duplicate must collapse + blank must drop; got agreed=%d dis=%d (%+v)", len(r.Agreed), len(r.Disagreements), r)
	}
	if !reflect.DeepEqual(r.Agreed[0].Reporters, []string{"ownsbom", "syft"}) {
		t.Errorf("a component listed twice by one producer must count it once: %+v", r.Agreed[0])
	}
}

func TestCrossCheckOrderIndependent(t *testing.T) {
	syft := doc("syft", comp("zlib", "1.0", "pkg:generic/zlib@1.0"), comp("acme", "2.0", "pkg:generic/acme@2.0"))
	owned := doc("ownsbom", comp("acme", "2.0", "pkg:generic/acme@2.0"))
	r1 := CrossCheck([]string{"syft", "ownsbom"}, []*SBOM{syft, owned})
	r2 := CrossCheck([]string{"ownsbom", "syft"}, []*SBOM{owned, syft})
	if !reflect.DeepEqual(r1, r2) {
		t.Errorf("cross-check must be order-independent:\n%+v\n%+v", r1, r2)
	}
}
