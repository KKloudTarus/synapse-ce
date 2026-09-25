package sca

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func goBinaryVulnerability(component, version, purl string) vulnerability.Vulnerability {
	return vulnerability.Vulnerability{
		ID: "CVE-2026-8100", Component: component, Version: version, Ecosystem: "Go", PackagePURL: purl,
		AffectedSymbols: []string{"example.com/module/pkg.Vulnerable"}, Severity: shared.SeverityHigh,
	}
}

func TestGoBinaryReachabilitySubjectsRequireCoherentGoIdentity(t *testing.T) {
	valid := goBinaryVulnerability("example.com/module", "v1.2.3", "pkg:golang/example.com/module@v1.2.3")
	stdlib := goBinaryVulnerability("go1.24.11", "1.24.11", "pkg:golang/stdlib@1.24.11")
	nonGo := valid
	nonGo.PackagePURL, nonGo.Ecosystem = "pkg:npm/example.com/module@v1.2.3", "npm"
	mismatch := valid
	mismatch.Version = "v1.2.4"
	missingPURL := valid
	missingPURL.PackagePURL = ""

	for _, tc := range []struct {
		name string
		v    vulnerability.Vulnerability
		doc  *sbom.SBOM
		want int
	}{
		{name: "valid module", v: valid, doc: &sbom.SBOM{Components: []sbom.Component{{Name: valid.Component, Version: valid.Version, PURL: valid.PackagePURL}}}, want: 1},
		{name: "stdlib identity normalizes but lacks ownership proof", v: stdlib, doc: &sbom.SBOM{Components: []sbom.Component{{Name: "go1.24.11", Version: "1.24.11", PURL: "pkg:golang/stdlib@1.24.11"}}}},
		{name: "non Go symbol collision", v: nonGo, doc: &sbom.SBOM{Components: []sbom.Component{{Name: nonGo.Component, Version: nonGo.Version, PURL: nonGo.PackagePURL}}}},
		{name: "advisory version mismatch", v: mismatch, doc: &sbom.SBOM{Components: []sbom.Component{{Name: "example.com/module", Version: "v1.2.3", PURL: "pkg:golang/example.com/module@v1.2.3"}}}},
		{name: "missing advisory PURL", v: missingPURL, doc: &sbom.SBOM{Components: []sbom.Component{{Name: valid.Component, Version: valid.Version, PURL: valid.PackagePURL}}}},
		{name: "SBOM identity mismatch", v: valid, doc: &sbom.SBOM{Components: []sbom.Component{{Name: valid.Component, Version: "v1.2.4", PURL: "pkg:golang/example.com/module@v1.2.4"}}}},
		{name: "missing SBOM", v: valid},
		{name: "SBOM has no Go identity", v: valid, doc: &sbom.SBOM{Components: []sbom.Component{{Name: "example", Version: "1.0.0", PURL: "pkg:npm/example@1.0.0"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := []finding.Finding{findingFor("f-1", tc.v)}
			subjects := goBinaryReachabilitySubjects(findings, []vulnerability.Vulnerability{tc.v}, tc.doc)
			if len(subjects) != tc.want {
				t.Fatalf("subjects = %+v, want %d", subjects, tc.want)
			}
			wantSymbol := tc.v.PackagePURL + "#" + tc.v.AffectedSymbols[0]
			if tc.want == 1 && (subjects[0].FindingID != "f-1" || len(subjects[0].Symbols) != 1 || subjects[0].Symbols[0] != wantSymbol) {
				t.Fatalf("subject = %+v", subjects[0])
			}
		})
	}
}

func TestGoBinaryReachabilitySubjectsKeepVersionsSeparateForSameSymbol(t *testing.T) {
	first := goBinaryVulnerability("example.com/module", "v1.2.3", "pkg:golang/example.com/module@v1.2.3")
	second := goBinaryVulnerability("example.com/module", "v1.2.4", "pkg:golang/example.com/module@v1.2.4")
	second.ID = "CVE-2026-8102"
	findings := []finding.Finding{findingFor("f-1", first), findingFor("f-2", second)}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: first.Component, Version: first.Version, PURL: first.PackagePURL},
		{Name: second.Component, Version: second.Version, PURL: second.PackagePURL},
	}}
	subjects := goBinaryReachabilitySubjects(findings, []vulnerability.Vulnerability{first, second}, doc)
	if len(subjects) != 2 || subjects[0].Symbols[0] == subjects[1].Symbols[0] {
		t.Fatalf("version-bound subjects = %+v", subjects)
	}
	if subjects[0].Symbols[0] != first.PackagePURL+"#"+first.AffectedSymbols[0] || subjects[1].Symbols[0] != second.PackagePURL+"#"+second.AffectedSymbols[0] {
		t.Fatalf("unexpected version-bound subjects = %+v", subjects)
	}
}

func TestGoBinaryReachabilitySubjectsRejectConflictingDuplicateDedupKeys(t *testing.T) {
	valid := goBinaryVulnerability("example.com/module", "v1.2.3", "pkg:golang/example.com/module@v1.2.3")
	conflicting := valid
	conflicting.PackagePURL = "pkg:golang/example.com/other@v1.2.3"
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: valid.Component, Version: valid.Version, PURL: valid.PackagePURL}}}
	if subjects := goBinaryReachabilitySubjects([]finding.Finding{findingFor("f-1", valid)}, []vulnerability.Vulnerability{valid, conflicting}, doc); len(subjects) != 0 {
		t.Fatalf("conflicting duplicate dedup key yielded subjects: %+v", subjects)
	}
}

type captureGoBinaryRecorder struct {
	calls    int
	subjects []ports.ReachabilitySubject
}

func (r *captureGoBinaryRecorder) Record(_ context.Context, _ shared.ID, _ string, subjects []ports.ReachabilitySubject) (int, error) {
	r.calls++
	r.subjects = append([]ports.ReachabilitySubject(nil), subjects...)
	return 0, nil
}

func TestGoBinaryReachabilityRejectsSubjectWithoutRemovingFinding(t *testing.T) {
	v := vulnerability.RawFinding{
		Source: "static", AdvisoryID: "CVE-2026-8101", Component: "example.com/module", Version: "v1.2.3",
		Ecosystem: "npm", PackagePURL: "pkg:npm/example.com/module@v1.2.3", Severity: shared.SeverityHigh,
		AffectedSymbols: []string{"example.com/module/pkg.Vulnerable"},
	}
	svc := NewService(
		&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil, ports.Provenance{},
		fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0, &fakeAcquirer{dir: t.TempDir()}, &fakeDetector{},
		staticSBOM{doc: &sbom.SBOM{Components: []sbom.Component{{Name: v.Component, Version: v.Version, PURL: v.PackagePURL}}}}, []ports.DetectionSource{staticVuln{v}}, nil, fakeLic{}, nil,
	)
	recorder := &captureGoBinaryRecorder{}
	svc.SetGoBinaryReachability(recorder)

	result, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeVulnerabilities})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].DedupKey != vulnerability.DedupKey(v.AdvisoryID, v.Component, v.Version) {
		t.Fatalf("rejected subject must leave its finding reported, findings=%+v", result.Findings)
	}
	if recorder.calls != 0 || len(recorder.subjects) != 0 {
		t.Fatalf("rejected Go-binary subject must mint no judgment, recorder=%+v", recorder)
	}
}
