package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func npmDoc() *sbom.SBOM {
	return &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.15", PURL: "pkg:npm/lodash@4.17.15"},
		{Name: "left-pad", Version: "1.0.0", PURL: "pkg:npm/left-pad@1.0.0"},
	}}
}

func vulnWith(component, version string, symbols ...string) vulnerability.Vulnerability {
	return vulnerability.Vulnerability{
		ID: "GHSA-" + component, Component: component, Version: version,
		AffectedSymbols: symbols,
	}
}

func findingFor(id string, v vulnerability.Vulnerability) finding.Finding {
	return finding.Finding{ID: shared.ID(id), DedupKey: vulnDedupKey(v)}
}

// TestJSSymbolSubjectsAreBuiltOnlyForAdvisoriesWithSymbols locks the precondition: Tier-2 asks "which
// export", so an advisory with no affected symbol has no Tier-2 question. Asking it anyway would compare
// a package name against export names and come back not-reached for everything.
func TestJSSymbolSubjectsAreBuiltOnlyForAdvisoriesWithSymbols(t *testing.T) {
	t.Parallel()

	withSymbols := vulnWith("lodash", "4.17.15", "template")
	without := vulnWith("left-pad", "1.0.0")
	findings := []finding.Finding{findingFor("f-1", withSymbols), findingFor("f-2", without)}
	vulns := []vulnerability.Vulnerability{withSymbols, without}

	subs := jsSymbolReachabilitySubjects(findings, vulns, npmDoc())
	if len(subs) != 1 {
		t.Fatalf("only the advisory naming an export gets a tier-2 subject, got %+v", subs)
	}
	if subs[0].FindingID != "f-1" {
		t.Fatalf("subject is keyed by the real finding id, got %q", subs[0].FindingID)
	}
	if len(subs[0].Symbols) != 1 || subs[0].Symbols[0] != "pkg:npm/lodash@4.17.15#template" {
		t.Fatalf("symbols = %v, want the exact component purl with the export appended", subs[0].Symbols)
	}
}

// A symbol that cannot be placed onto an export name is DROPPED rather than passed through: it could
// never match an export, so it would be sealed as a false negative at full confidence.
func TestUnplaceableSymbolsAreDropped(t *testing.T) {
	t.Parallel()

	v := vulnWith("lodash", "4.17.15", "lodash/template", "Class.prototype.method", "*", "lodash.merge", "template")
	subs := jsSymbolReachabilitySubjects([]finding.Finding{findingFor("f-1", v)}, []vulnerability.Vulnerability{v}, npmDoc())
	if len(subs) != 1 {
		t.Fatalf("expected one subject, got %+v", subs)
	}
	want := map[string]bool{
		"pkg:npm/lodash@4.17.15#merge":    true,
		"pkg:npm/lodash@4.17.15#template": true,
	}
	if len(subs[0].Symbols) != len(want) {
		t.Fatalf("symbols = %v, want only the two placeable exports", subs[0].Symbols)
	}
	for _, symbol := range subs[0].Symbols {
		if !want[symbol] {
			t.Fatalf("unexpected symbol %q", symbol)
		}
	}
}

// A component with no exact identity in this document has no subject to answer for — the version the
// advisory names must be the version the SBOM records, or the verdict would be about a different build.
func TestSubjectsNeedAnExactComponentIdentity(t *testing.T) {
	t.Parallel()

	v := vulnWith("lodash", "4.17.21", "template") // a version the document does not contain
	if subs := jsSymbolReachabilitySubjects([]finding.Finding{findingFor("f-1", v)}, []vulnerability.Vulnerability{v}, npmDoc()); len(subs) != 0 {
		t.Fatalf("a version absent from the document must yield no subject, got %+v", subs)
	}
	if subs := jsSymbolReachabilitySubjects([]finding.Finding{findingFor("f-1", v)}, []vulnerability.Vulnerability{v}, nil); len(subs) != 0 {
		t.Fatalf("no document means no subject, got %+v", subs)
	}
	// A non-npm document produces nothing either.
	other := &sbom.SBOM{Components: []sbom.Component{{Name: "flask", Version: "1.0", PURL: "pkg:pypi/flask@1.0"}}}
	if subs := jsSymbolReachabilitySubjects([]finding.Finding{findingFor("f-1", v)}, []vulnerability.Vulnerability{v}, other); len(subs) != 0 {
		t.Fatalf("a document with no npm components must yield no subject, got %+v", subs)
	}
}
