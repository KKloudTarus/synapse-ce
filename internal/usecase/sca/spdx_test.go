package sca

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestBuildSPDXDeterministicAndValid(t *testing.T) {
	doc := &sbom.SBOM{
		TargetRef: "https://github.com/org/repo",
		Components: []sbom.Component{
			{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Licenses: []sbom.License{{SPDXID: "MIT"}}},
			{Name: "express", Version: "4.18.2", PURL: "pkg:npm/express@4.18.2"},
		},
	}
	created := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)

	a := buildSPDX(doc, doc.TargetRef, created)
	b := buildSPDX(doc, doc.TargetRef, created)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatal("buildSPDX must be deterministic")
	}
	if a.SPDXVersion != "SPDX-2.3" || a.DataLicense != "CC0-1.0" || a.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("spdx header wrong: %+v", a)
	}
	if len(a.Packages) != 2 {
		t.Fatalf("want 2 packages, got %d", len(a.Packages))
	}
	// sorted by name: express before lodash
	if a.Packages[0].Name != "express" || a.Packages[1].Name != "lodash" {
		t.Errorf("packages not sorted: %s, %s", a.Packages[0].Name, a.Packages[1].Name)
	}
	if a.Packages[1].LicenseDeclared != "MIT" {
		t.Errorf("lodash license = %q, want MIT", a.Packages[1].LicenseDeclared)
	}
	if a.Packages[0].LicenseDeclared != "NOASSERTION" {
		t.Errorf("express license = %q, want NOASSERTION", a.Packages[0].LicenseDeclared)
	}
	if len(a.Packages[1].ExternalRefs) != 1 || a.Packages[1].ExternalRefs[0].ReferenceLocator != "pkg:npm/lodash@4.17.21" {
		t.Errorf("purl externalRef missing: %+v", a.Packages[1].ExternalRefs)
	}
	if len(a.Relationships) != 2 || a.Relationships[0].RelationshipType != "DESCRIBES" {
		t.Errorf("relationships wrong: %+v", a.Relationships)
	}
}

func TestBuildSPDXEmitsSupplier(t *testing.T) {
	doc := &sbom.SBOM{
		TargetRef: "https://github.com/org/repo",
		Components: []sbom.Component{
			{Name: "commons-lang3", Version: "3.12.0", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.12.0", Supplier: "org.apache.commons"},
			{Name: "leftpad", Version: "1.0.0", PURL: "pkg:npm/leftpad@1.0.0"}, // no supplier
		},
	}
	a := buildSPDX(doc, doc.TargetRef, time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC))
	byName := map[string]spdxPackage{}
	for _, p := range a.Packages {
		byName[p.Name] = p
	}
	if got := byName["commons-lang3"].Supplier; got != "Organization: org.apache.commons" {
		t.Errorf("PackageSupplier = %q, want \"Organization: org.apache.commons\"", got)
	}
	if got := byName["leftpad"].Supplier; got != "" {
		t.Errorf("a component with no supplier must omit PackageSupplier, got %q", got)
	}
}

func TestScanTimePinned(t *testing.T) {
	r := ScanResult{VulnDBSnapshot: "osv.dev@2026-06-21T10:00:00Z"}
	if got := r.scanTime(); got.Format(time.RFC3339) != "2026-06-21T10:00:00Z" {
		t.Errorf("scanTime = %v, want pinned from snapshot", got)
	}
	// no snapshot -> stable zero time, never time.Now()
	if (ScanResult{}).scanTime() != time.Unix(0, 0).UTC() {
		t.Error("scanTime fallback must be the stable zero time")
	}
}
