package modulegraph

import (
	"strings"
	"testing"
)

func moduleGraphWith(evidence *SymbolEvidence) Graph {
	return Graph{
		Modules:        []Module{{Path: "src/a.ts", Dialect: DialectTypeScript}},
		SymbolEvidence: evidence,
	}
}

// TestSymbolEvidenceCompleteDistinguishesNotCollectedFromEmpty is the safety property the pointer
// exists for: only "collected, and nothing limited it" permits a negative conclusion.
func TestSymbolEvidenceCompleteDistinguishesNotCollectedFromEmpty(t *testing.T) {
	t.Parallel()

	var uncollected *SymbolEvidence
	if uncollected.Complete() {
		t.Fatal("evidence that was never collected is not complete evidence")
	}
	if (&SymbolEvidence{Coverage: []CoverageIssue{{Kind: CoverageSymbolEvidenceIncomplete}}}).Complete() {
		t.Fatal("evidence with a coverage limitation is not complete")
	}
	if !(&SymbolEvidence{}).Complete() {
		t.Fatal("evidence that was collected and found nothing IS complete — that is the whole distinction")
	}
}

// A use whose module was never scanned is an ERROR, not a dropped record: silently discarding a
// reference is how an export that IS reached comes to look unused.
func TestNormalizeRefusesAUseFromAnUnknownModule(t *testing.T) {
	t.Parallel()

	_, err := Normalize(moduleGraphWith(&SymbolEvidence{Uses: []LocalUse{
		{Module: "src/ghost.ts", Local: "_", Kind: LocalUseOpaque},
	}}))
	if err == nil {
		t.Fatal("a reference from a module that was never scanned must be refused, not dropped")
	}
	if !strings.Contains(err.Error(), "not a known module") {
		t.Fatalf("error %q must name the problem", err)
	}

	if _, err := Normalize(moduleGraphWith(&SymbolEvidence{JSXModules: []string{"src/ghost.ts"}})); err == nil {
		t.Fatal("a jsx module that was never scanned must be refused")
	}
}

func TestNormalizeValidatesLocalUses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		use  LocalUse
	}{
		{"unknown kind", LocalUse{Module: "src/a.ts", Local: "_", Kind: "guess"}},
		{"negative line", LocalUse{Module: "src/a.ts", Local: "_", Kind: LocalUseOpaque, Line: -1}},
		{"no local", LocalUse{Module: "src/a.ts", Kind: LocalUseOpaque}},
		// A property use must name the property, and an opaque use must NOT: an opaque reference is
		// exactly one whose reached export is unknown, so carrying a property would misrepresent it.
		{"property use with no property", LocalUse{Module: "src/a.ts", Local: "_", Kind: LocalUseProperty}},
		{"opaque use with a property", LocalUse{Module: "src/a.ts", Local: "_", Property: "x", Kind: LocalUseOpaque}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Normalize(moduleGraphWith(&SymbolEvidence{Uses: []LocalUse{test.use}})); err == nil {
				t.Fatalf("%s must be refused", test.name)
			}
		})
	}
}

// Normalization is deterministic: identical evidence collapses, and the FIRST line survives so a reader
// is pointed at the earliest occurrence.
func TestNormalizeDeduplicatesAndOrdersSymbolEvidence(t *testing.T) {
	t.Parallel()

	graph := Graph{
		Modules: []Module{{Path: "src/a.ts", Dialect: DialectTypeScript}, {Path: "src/b.ts", Dialect: DialectTypeScript}},
		SymbolEvidence: &SymbolEvidence{
			Uses: []LocalUse{
				{Module: "src/b.ts", Local: "_", Property: "merge", Kind: LocalUseProperty, Line: 9},
				{Module: "src/a.ts", Local: "_", Property: "merge", Kind: LocalUseProperty, Line: 7},
				{Module: "src/a.ts", Local: "_", Property: "merge", Kind: LocalUseProperty, Line: 3},
			},
			JSXModules: []string{"src/b.ts", "src/a.ts", "src/b.ts"},
		},
	}
	out, err := Normalize(graph)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(out.SymbolEvidence.Uses) != 2 {
		t.Fatalf("identical evidence must collapse, got %+v", out.SymbolEvidence.Uses)
	}
	if out.SymbolEvidence.Uses[0].Module != "src/a.ts" || out.SymbolEvidence.Uses[0].Line != 3 {
		t.Fatalf("the earliest occurrence must survive in sorted order, got %+v", out.SymbolEvidence.Uses[0])
	}
	if len(out.SymbolEvidence.JSXModules) != 2 || out.SymbolEvidence.JSXModules[0] != "src/a.ts" {
		t.Fatalf("jsx modules = %v, want sorted and deduplicated", out.SymbolEvidence.JSXModules)
	}

	// Nil stays nil: "not collected" must survive normalization as a distinct state.
	empty, err := Normalize(moduleGraphWith(nil))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if empty.SymbolEvidence != nil {
		t.Fatal("uncollected symbol evidence must stay uncollected")
	}
}
