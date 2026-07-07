package sbom

import (
	"strings"
	"testing"
	"time"
)

func TestSupplierFromPURL(t *testing.T) {
	cases := map[string]string{
		"pkg:maven/org.apache.commons/commons-lang3@3.12.0": "org.apache.commons", // Maven groupId
		"pkg:npm/%40angular/core@17.0.0":                    "@angular",           // npm scope, percent-decoded
		"pkg:golang/github.com/gin-gonic/gin@v1.9.1":        "github.com/gin-gonic",
		"pkg:npm/leftpad@1.0.0":                             "", // bare name, no namespace => no guess
		"pkg:pypi/requests@2.31.0":                          "", // pypi has no namespace
		"":                                                  "",
		"not-a-purl":                                        "",
		"pkg:":                                              "",
		"pkg:deb/debian/curl@7.88.1?arch=amd64":             "debian", // qualifiers stripped
	}
	for in, want := range cases {
		if got := SupplierFromPURL(in); got != want {
			t.Errorf("SupplierFromPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSupplierOr(t *testing.T) {
	// Declared supplier wins; else derive from the PURL namespace; else empty.
	if got := SupplierOr("Acme Corp", "pkg:pypi/requests@2.31.0"); got != "Acme Corp" {
		t.Errorf("declared supplier must win, got %q", got)
	}
	if got := SupplierOr("  ", "pkg:maven/org.apache.commons/commons-lang3@3.12.0"); got != "org.apache.commons" {
		t.Errorf("blank declared must fall back to PURL namespace, got %q", got)
	}
	if got := SupplierOr("", "pkg:pypi/requests@2.31.0"); got != "" {
		t.Errorf("no declared + no namespace must be empty, got %q", got)
	}
}

func TestSupplierWithSource(t *testing.T) {
	cases := []struct{ declared, purl, wantSup, wantSrc string }{
		{"Acme Corp", "pkg:pypi/requests@2.31.0", "Acme Corp", SupplierDeclared},
		{"", "pkg:maven/org.apache.commons/commons-lang3@3.12.0", "org.apache.commons", SupplierDerived},
		{"  ", "pkg:npm/%40angular/core@17.0.0", "@angular", SupplierDerived},
		{"", "pkg:pypi/requests@2.31.0", "", ""},
	}
	for _, c := range cases {
		sup, src := SupplierWithSource(c.declared, c.purl)
		if sup != c.wantSup || src != c.wantSrc {
			t.Errorf("SupplierWithSource(%q,%q) = (%q,%q), want (%q,%q)", c.declared, c.purl, sup, src, c.wantSup, c.wantSrc)
		}
	}
}

func TestQualityCreditsExplicitSupplier(t *testing.T) {
	// A component with NO PURL (so no derivable supplier) but an explicitly-captured Supplier must still
	// count toward the NTIA supplier element.
	doc := SBOM{
		Source:     "synapse",
		Components: []Component{{Name: "internal-lib", Version: "1.0.0", Supplier: "Acme Corp"}},
	}
	doc.Audit.CreatedAt = time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	byID := map[string]QualityElement{}
	for _, e := range Quality(doc).Elements {
		byID[e.ID] = e
	}
	if byID["ntia-supplier"].Score != 100 {
		t.Errorf("an explicit Supplier must satisfy the supplier element even with no PURL, got %d", byID["ntia-supplier"].Score)
	}
}

func fullComponent() Component {
	return Component{
		Name:     "gin",
		Version:  "v1.9.1",
		PURL:     "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
		Licenses: []License{{Name: "MIT", SPDXID: "MIT"}},
		SHA1:     "0123456789abcdef0123456789abcdef01234567",
	}
}

func TestQualityFullSBOMMeetsNTIA(t *testing.T) {
	doc := SBOM{
		Source:       "synapse",
		Components:   []Component{fullComponent()},
		Dependencies: []Dependency{{Ref: "gin", DependsOn: []string{}}},
	}
	doc.Audit.CreatedAt = time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)

	r := Quality(doc)
	if !r.NTIAMet {
		t.Fatalf("a fully-described SBOM must meet NTIA, got %d/100 not met: %s", r.NTIAScore, r.Summary)
	}
	if r.NTIAScore != 100 {
		t.Errorf("NTIAScore = %d, want 100", r.NTIAScore)
	}
	if r.Score != 100 {
		t.Errorf("blended Score = %d, want 100 (all semantic present too)", r.Score)
	}
	if !strings.Contains(r.Summary, "all minimum elements present") {
		t.Errorf("summary should confirm NTIA met, got %q", r.Summary)
	}
}

func TestQualityThinSBOMSurfacesGaps(t *testing.T) {
	// Names only: no supplier (no PURL), no version, no PURL, no license, no checksum,
	// no dependency graph. Author + timestamp present at the doc level.
	doc := SBOM{
		Source:     "synapse",
		Components: []Component{{Name: "mystery"}, {Name: "other"}},
	}
	doc.Audit.CreatedAt = time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)

	r := Quality(doc)
	if r.NTIAMet {
		t.Fatal("a names-only SBOM must NOT meet NTIA")
	}
	byID := map[string]QualityElement{}
	for _, e := range r.Elements {
		byID[e.ID] = e
	}
	if byID["ntia-name"].Score != 100 {
		t.Errorf("both components are named, want name score 100, got %d", byID["ntia-name"].Score)
	}
	for _, id := range []string{"ntia-supplier", "ntia-version", "ntia-uniqid", "sem-license", "sem-checksum"} {
		if byID[id].Score != 0 {
			t.Errorf("%s should score 0 for a names-only SBOM, got %d", id, byID[id].Score)
		}
		if byID[id].Detail == "" {
			t.Errorf("%s below 100 must carry an explanatory Detail", id)
		}
	}
	if byID["ntia-dependencies"].Score != 0 {
		t.Errorf("a flat list has no dependency relationships, want 0, got %d", byID["ntia-dependencies"].Score)
	}
	if byID["ntia-author"].Score != 100 || byID["ntia-timestamp"].Score != 100 {
		t.Error("author + timestamp are present at the doc level and must score 100")
	}
	if !strings.Contains(r.Summary, "Supplier name") || !strings.Contains(r.Summary, "below the") {
		t.Errorf("summary should name the weak NTIA elements, got %q", r.Summary)
	}
}

func TestQualityPartialRatio(t *testing.T) {
	// One of two components fully described, the other bare — element scores should be 50.
	doc := SBOM{
		Source:     "synapse",
		Components: []Component{fullComponent(), {Name: "bare"}},
	}
	doc.Audit.CreatedAt = time.Now().UTC()
	r := Quality(doc)
	byID := map[string]QualityElement{}
	for _, e := range r.Elements {
		byID[e.ID] = e
	}
	if got := byID["ntia-supplier"].Score; got != 50 {
		t.Errorf("supplier present on 1 of 2 components, want 50, got %d", got)
	}
	if got := byID["sem-license"].Score; got != 50 {
		t.Errorf("license present on 1 of 2, want 50, got %d", got)
	}
	if !strings.Contains(byID["ntia-supplier"].Detail, "1 of 2 components") {
		t.Errorf("detail should quantify the gap, got %q", byID["ntia-supplier"].Detail)
	}
}

func TestHasChecksumAndScorerCreditsChecksums(t *testing.T) {
	// A component with a Checksums entry (npm/pnpm SRI) but no legacy SHA1 must count as having a checksum.
	withCk := Component{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Checksums: []Checksum{{Algorithm: "SHA512", Value: "aaa"}}}
	if !HasChecksum(withCk) {
		t.Error("a component with a Checksums entry must report HasChecksum")
	}
	if HasChecksum(Component{Name: "bare"}) {
		t.Error("a component with neither SHA1 nor Checksums must not report HasChecksum")
	}
	if !HasChecksum(Component{SHA1: "abc"}) {
		t.Error("the legacy SHA1 field must still count as a checksum")
	}
	doc := SBOM{Source: "synapse", Components: []Component{withCk}}
	doc.Audit.CreatedAt = time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	for _, e := range Quality(doc).Elements {
		if e.ID == "sem-checksum" && e.Score != 100 {
			t.Errorf("sem-checksum = %d, want 100 for a Checksums-only component", e.Score)
		}
	}
}

func TestQualityScoreClampedWhenNTIAUnmet(t *testing.T) {
	// A component fully described EXCEPT supplier (a bare-namespace PURL): every semantic check passes, so
	// the raw blend lands at the threshold — but a missing NTIA minimum element must keep the headline Score
	// visibly below NTIAThreshold so a gate that (wrongly) keys off Score can't read it as passing.
	doc := SBOM{
		Source: "synapse",
		Components: []Component{{
			Name:     "requests",
			Version:  "2.31.0",
			PURL:     "pkg:pypi/requests@2.31.0", // pypi has no namespace => supplier unresolved
			Licenses: []License{{Name: "Apache-2.0", SPDXID: "Apache-2.0"}},
			SHA1:     "0123456789abcdef0123456789abcdef01234567",
		}},
		Dependencies: []Dependency{{Ref: "requests"}},
	}
	doc.Audit.CreatedAt = time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)

	r := Quality(doc)
	if r.NTIAMet {
		t.Fatal("a supplier-less SBOM must not meet NTIA")
	}
	if r.Score >= NTIAThreshold {
		t.Errorf("Score must be clamped below NTIAThreshold (%d) when NTIA is unmet, got %d", NTIAThreshold, r.Score)
	}
}

func TestQualityEmptySBOMScoresZeroNotPanic(t *testing.T) {
	r := Quality(SBOM{}) // no source, no timestamp, no components
	if r.Score != 0 {
		t.Errorf("an empty SBOM should score 0, got %d", r.Score)
	}
	if r.NTIAMet {
		t.Error("an empty SBOM cannot meet NTIA")
	}
	// Component-level elements must report the empty case explicitly, not silently pass.
	for _, e := range r.Elements {
		if e.Total == 0 && e.Detail == "" {
			t.Errorf("component element %s over an empty SBOM must carry a Detail", e.ID)
		}
	}
}

func TestQualityComplianceProfiles(t *testing.T) {
	profileByID := func(r QualityReport) map[string]ProfileResult {
		m := map[string]ProfileResult{}
		for _, p := range r.Profiles {
			m[p.ID] = p
		}
		return m
	}

	// A fully described SBOM meets both profiles.
	full := SBOM{Source: "synapse", Components: []Component{fullComponent()}, Dependencies: []Dependency{{Ref: "gin"}}}
	full.Audit.CreatedAt = time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	fp := profileByID(Quality(full))
	if !fp["ntia-2021"].Met || !fp["vuln-lookup"].Met {
		t.Errorf("a full SBOM must pass both profiles, got ntia=%+v vuln=%+v", fp["ntia-2021"], fp["vuln-lookup"])
	}

	// Supplier-less but otherwise complete: NTIA-2021 fails naming Supplier; vuln-lookup still passes
	// (name+version+PURL present).
	noSupplier := SBOM{
		Source:       "synapse",
		Components:   []Component{{Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0", Licenses: []License{{SPDXID: "Apache-2.0"}}, SHA1: "abc"}},
		Dependencies: []Dependency{{Ref: "requests"}},
	}
	noSupplier.Audit.CreatedAt = time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	np := profileByID(Quality(noSupplier))
	if np["ntia-2021"].Met {
		t.Error("a supplier-less SBOM must FAIL NTIA-2021")
	}
	if len(np["ntia-2021"].Missing) != 1 || np["ntia-2021"].Missing[0] != "Supplier name" {
		t.Errorf("NTIA-2021 must name the missing Supplier element, got %v", np["ntia-2021"].Missing)
	}
	if !strings.Contains(np["ntia-2021"].Summary, "FAIL") {
		t.Errorf("failing profile summary must say FAIL, got %q", np["ntia-2021"].Summary)
	}
	if !np["vuln-lookup"].Met {
		t.Error("name+version+PURL present must PASS vuln-lookup readiness even without a supplier")
	}

	// A bare (name-only) component fails vuln-lookup too.
	bare := SBOM{Source: "synapse", Components: []Component{{Name: "mystery"}}}
	bare.Audit.CreatedAt = time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	if profileByID(Quality(bare))["vuln-lookup"].Met {
		t.Error("a version-less, PURL-less component must FAIL vuln-lookup readiness")
	}
}

func TestNTIAProfileMatchesNTIAMet(t *testing.T) {
	// The ntia-2021 profile requires exactly the NTIA elements at the same threshold as NTIAMet, so the two
	// must never disagree. This guard fails loudly if a future NTIA element is added to the scorer but not the
	// profile table (or vice versa).
	full := SBOM{Source: "synapse", Components: []Component{fullComponent()}, Dependencies: []Dependency{{Ref: "gin"}}}
	full.Audit.CreatedAt = time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	cases := []SBOM{
		full,
		{Source: "synapse", Components: []Component{{Name: "bare"}}}, // fails many NTIA elements
		{Source: "", Components: []Component{fullComponent()}},       // missing author + timestamp
		{Components: nil}, // empty
	}
	for i, doc := range cases {
		r := Quality(doc)
		var ntia ProfileResult
		for _, p := range r.Profiles {
			if p.ID == "ntia-2021" {
				ntia = p
			}
		}
		if ntia.Met != r.NTIAMet {
			t.Errorf("case %d: ntia-2021 profile Met=%v but NTIAMet=%v — the two must agree", i, ntia.Met, r.NTIAMet)
		}
	}
}

func TestQualityDeterministicOrder(t *testing.T) {
	doc := SBOM{Source: "synapse", Components: []Component{fullComponent()}}
	doc.Audit.CreatedAt = time.Now().UTC()
	first := Quality(doc)
	var ids []string
	for _, e := range first.Elements {
		ids = append(ids, e.ID)
	}
	joined := strings.Join(ids, "|")
	for i := 0; i < 5; i++ {
		got := Quality(doc)
		var gotIDs []string
		for _, e := range got.Elements {
			gotIDs = append(gotIDs, e.ID)
		}
		if strings.Join(gotIDs, "|") != joined {
			t.Fatal("element order must be deterministic")
		}
	}
	// NTIA category must sort before semantic.
	if !strings.HasPrefix(first.Elements[0].Category, QualityCategoryNTIA) {
		t.Errorf("first element should be NTIA, got %q", first.Elements[0].Category)
	}
}
