package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestJSReachabilitySubjectsUseExactPURLs(t *testing.T) {
	t.Parallel()

	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		{Name: "lodash", Version: "3.10.1", PURL: "pkg:npm/lodash@3.10.1"},
		{Name: "requests", Version: "2.0.0", PURL: "pkg:pypi/requests@2.0.0"},
	}}
	vulns := []vulnerability.Vulnerability{
		{ID: "A1", Component: "lodash", Version: "4.17.21"},
		{ID: "A2", Component: "requests", Version: "2.0.0"},
	}
	findings := []finding.Finding{
		{ID: "f1", DedupKey: vulnDedupKey(vulns[0])},
		{ID: "f2", DedupKey: vulnDedupKey(vulns[1])},
	}

	subs := jsReachabilitySubjects(findings, vulns, doc)
	if len(subs) != 1 {
		t.Fatalf("only the npm finding may produce a subject, got %+v", subs)
	}
	// The subject must name the EXACT version, not just the package: two versions of lodash are
	// installed, and a name alone would not say which one a verdict is about.
	if subs[0].Symbols[0] != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("subject = %q, want the exact component purl", subs[0].Symbols[0])
	}
	if subs[0].FindingID != "f1" {
		t.Fatalf("subject finding = %q, want f1", subs[0].FindingID)
	}
}

func TestJSReachabilitySubjectsSkipUnmatchedComponents(t *testing.T) {
	t.Parallel()

	// Without an exact component identity there is no subject to answer for; inventing one would let a
	// verdict be attached to the wrong package.
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}
	vulns := []vulnerability.Vulnerability{{ID: "A1", Component: "lodash", Version: "9.9.9"}}
	findings := []finding.Finding{{ID: "f1", DedupKey: vulnDedupKey(vulns[0])}}

	if subs := jsReachabilitySubjects(findings, vulns, doc); len(subs) != 0 {
		t.Fatalf("a version with no matching component must yield no subject, got %+v", subs)
	}
}

func TestJSReachabilitySubjectsHandleNoSBOM(t *testing.T) {
	t.Parallel()
	if subs := jsReachabilitySubjects(nil, nil, nil); subs != nil {
		t.Fatalf("no sbom means no subjects, got %+v", subs)
	}
}
