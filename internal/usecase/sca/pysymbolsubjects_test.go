package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/pyreach"
)

func TestPythonTier2SubjectsRequireExactComponentAndAffectedSymbols(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0"}}}
	with := vulnerability.Vulnerability{ID: "CVE-1", Component: "requests", Version: "2.31.0", AffectedSymbols: []string{"requests.sessions.Session.request"}}
	without := vulnerability.Vulnerability{ID: "CVE-2", Component: "requests", Version: "2.31.0"}
	subjects := pySymbolReachabilitySubjects([]finding.Finding{findingFor("f-1", with), findingFor("f-2", without)}, []vulnerability.Vulnerability{with, without}, doc)
	if len(subjects) != 1 || subjects[0].FindingID != "f-1" || len(subjects[0].Symbols) != 1 {
		t.Fatalf("subjects = %+v", subjects)
	}
	if _, symbol, ok := pyreach.ParseSymbolSubject(subjects[0].Symbols[0]); !ok || symbol != with.AffectedSymbols[0] {
		t.Fatalf("encoded subject = %q", subjects[0].Symbols[0])
	}
}

func TestPythonTier2SubjectsDropWholeFindingOnMalformedSymbol(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0"}}}
	vuln := vulnerability.Vulnerability{
		ID: "CVE-1", Component: "requests", Version: "2.31.0",
		AffectedSymbols: []string{"requests.get", "requests.get()"},
	}
	if subjects := pySymbolReachabilitySubjects([]finding.Finding{findingFor("f-1", vuln)}, []vulnerability.Vulnerability{vuln}, doc); len(subjects) != 0 {
		t.Fatalf("malformed advisory symbol must drop the finding: %+v", subjects)
	}
}

func TestPythonTier2SubjectsNeedMatchingVersion(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "requests", Version: "2.30.0", PURL: "pkg:pypi/requests@2.30.0"}}}
	vuln := vulnerability.Vulnerability{ID: "CVE-1", Component: "requests", Version: "2.31.0", AffectedSymbols: []string{"requests.get"}}
	if subjects := pySymbolReachabilitySubjects([]finding.Finding{findingFor("f-1", vuln)}, []vulnerability.Vulnerability{vuln}, doc); len(subjects) != 0 {
		t.Fatalf("mismatched component version produced subjects: %+v", subjects)
	}
}
