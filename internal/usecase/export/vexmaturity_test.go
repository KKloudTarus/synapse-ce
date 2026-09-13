package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestOpenVEXPerStatementTimestampAndContentID(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	doc := buildOpenVEX("e1", vexInputData{findings: sampleFindings()}, now, "v1", "")

	for _, s := range doc.Statements {
		if s.Timestamp == "" {
			t.Errorf("every statement must carry a timestamp, got %+v", s)
		}
	}
	// A per-finding EvaluatedAt is used for that statement's timestamp; a finding without one inherits the
	// document time.
	evaluated := time.Unix(5000, 0).UTC()
	custom := []finding.Finding{
		{ID: "f1", EngagementID: "e1", Status: finding.StatusOpen, DedupKey: "vuln:CVE-2020-7471:django:2.2.0", EvaluatedAt: &evaluated},
	}
	doc2 := buildOpenVEX("e1", vexInputData{findings: custom}, now, "v1", "")
	if len(doc2.Statements) != 1 || doc2.Statements[0].Timestamp != evaluated.Format(time.RFC3339) {
		t.Errorf("statement must use the finding's EvaluatedAt, got %+v", doc2.Statements)
	}

	// The @id is content-addressed: identical findings yield an identical @id; a changed set yields a new one.
	again := buildOpenVEX("e1", vexInputData{findings: sampleFindings()}, now.Add(time.Hour), "v1", "")
	if doc.ID != again.ID {
		t.Errorf("an unchanged re-export must be idempotent: %q != %q", doc.ID, again.ID)
	}
	fewer := buildOpenVEX("e1", vexInputData{findings: sampleFindings()[:1]}, now, "v1", "")
	if doc.ID == fewer.ID {
		t.Errorf("a changed finding set must change the @id, both were %q", doc.ID)
	}
}

func TestOpenVEXSupersedes(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	doc := buildOpenVEX("e1", vexInputData{findings: sampleFindings()}, now, "v1", "https://example/vex/e1@deadbeef")
	if len(doc.Supersedes) != 1 || doc.Supersedes[0].ID != "https://example/vex/e1@deadbeef" {
		t.Errorf("supersedes must reference the prior @id, got %+v", doc.Supersedes)
	}
	none := buildOpenVEX("e1", vexInputData{findings: sampleFindings()}, now, "v1", "")
	if none.Supersedes != nil {
		t.Errorf("no supersedes when none passed, got %+v", none.Supersedes)
	}
}

func TestCSAFVEXStructure(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	doc := buildCSAFVEX("e1", vexInputData{findings: sampleFindings()}, now, "v1")

	if doc.Document.Category != "csaf_vex" || doc.Document.CSAFVersion != "2.0" {
		t.Fatalf("bad CSAF document header: %+v", doc.Document)
	}
	if doc.Document.Publisher.Category != "vendor" || doc.Document.Tracking.ID == "" {
		t.Fatalf("bad publisher/tracking: %+v", doc.Document)
	}
	if len(doc.Document.Tracking.RevisionHistory) != 1 {
		t.Errorf("tracking must carry a revision history, got %+v", doc.Document.Tracking)
	}
	// One product (django@2.2.0), two vulnerabilities (one affected, one not_affected).
	if len(doc.ProductTree.FullProductNames) != 1 || doc.ProductTree.FullProductNames[0].Name != "django@2.2.0" {
		t.Fatalf("product tree = %+v", doc.ProductTree)
	}
	pid := doc.ProductTree.FullProductNames[0].ProductID
	byCVE := map[string]CSAFVulnerability{}
	for _, v := range doc.Vulnerabilities {
		byCVE[v.CVE] = v
	}
	if v := byCVE["CVE-2020-7471"]; len(v.ProductStatus.KnownAffected) != 1 || v.ProductStatus.KnownAffected[0] != pid {
		t.Errorf("affected vuln must be known_affected for the product, got %+v", v)
	}
	na := byCVE["CVE-2019-14234"]
	if len(na.ProductStatus.KnownNotAffected) != 1 || na.ProductStatus.KnownNotAffected[0] != pid {
		t.Errorf("false-positive must be known_not_affected, got %+v", na)
	}
	if len(na.Flags) != 1 || na.Flags[0].Label != "vulnerable_code_not_present" || na.Flags[0].ProductIDs[0] != pid {
		t.Errorf("not_affected must carry a justification flag, got %+v", na.Flags)
	}
}

func TestCSAFVEXNonCVEUsesIDs(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	fs := []finding.Finding{
		{ID: "g1", EngagementID: "e1", Status: finding.StatusOpen, Severity: shared.SeverityHigh, DedupKey: "vuln:GHSA-xxxx-yyyy-zzzz:lodash:4.0.0"},
	}
	doc := buildCSAFVEX("e1", vexInputData{findings: fs}, now, "v1")
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(doc.Vulnerabilities))
	}
	v := doc.Vulnerabilities[0]
	if v.CVE != "" || len(v.IDs) != 1 || v.IDs[0].SystemName != "GitHub Security Advisory" || v.IDs[0].Text != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("a GHSA advisory must use ids, not cve, got %+v", v)
	}
}

// The CSAF and OpenVEX emitters must assert the same statuses over the same advisories (both read the same
// records), so a consumer of either format sees an identical exploitability posture.
func TestCSAFAndOpenVEXAgree(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	ovex := buildOpenVEX("e1", vexInputData{findings: sampleFindings()}, now, "v1", "")
	csaf := buildCSAFVEX("e1", vexInputData{findings: sampleFindings()}, now, "v1")

	ovexStatus := map[string]string{}
	for _, s := range ovex.Statements {
		ovexStatus[s.Vulnerability.Name] = s.Status
	}
	for _, v := range csaf.Vulnerabilities {
		id := v.CVE
		if id == "" && len(v.IDs) > 0 {
			id = v.IDs[0].Text
		}
		want := ovexStatus[id]
		got := ""
		switch {
		case len(v.ProductStatus.KnownAffected) > 0:
			got = "affected"
		case len(v.ProductStatus.KnownNotAffected) > 0:
			got = "not_affected"
		case len(v.ProductStatus.Fixed) > 0:
			got = "fixed"
		}
		if got != want {
			t.Errorf("CSAF status for %s = %q, OpenVEX = %q", id, got, want)
		}
	}
}

// An engagement with no publishable vuln findings must not emit CSAF empty arrays (which CSAF rejects):
// product_tree and vulnerabilities are omitted from the JSON entirely.
func TestCSAFVEXEmptyOmitsArrays(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	doc := buildCSAFVEX("e1", vexInputData{findings: nil}, now, "v1")
	if doc.ProductTree != nil {
		t.Errorf("empty product_tree must be a nil pointer, got %+v", doc.ProductTree)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "\"product_tree\"") || strings.Contains(string(body), "\"vulnerabilities\"") {
		t.Errorf("empty product_tree/vulnerabilities must be omitted from JSON, got %s", body)
	}
}

// Two findings for the SAME advisory+product with conflicting statuses (open + false_positive) must resolve
// to the more-exploitable one (affected), never emit the product in both buckets, and never assert
// not_affected while an affected finding exists.
func TestVEXConflictResolvesToAffected(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	fs := []finding.Finding{
		{ID: "a", EngagementID: "e1", Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-2024-0001:pkg:1.0"},
		{ID: "b", EngagementID: "e1", Status: finding.StatusOpen, DedupKey: "vuln:CVE-2024-0001:pkg:1.0"},
	}
	ovex := buildOpenVEX("e1", vexInputData{findings: fs}, now, "v1", "")
	if len(ovex.Statements) != 1 || ovex.Statements[0].Status != "affected" {
		t.Fatalf("conflict must collapse to one affected statement, got %+v", ovex.Statements)
	}
	csaf := buildCSAFVEX("e1", vexInputData{findings: fs}, now, "v1")
	if len(csaf.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(csaf.Vulnerabilities))
	}
	v := csaf.Vulnerabilities[0]
	if len(v.ProductStatus.KnownNotAffected) != 0 {
		t.Errorf("a product with an affected finding must NOT appear in known_not_affected, got %+v", v.ProductStatus)
	}
	if len(v.ProductStatus.KnownAffected) != 1 {
		t.Errorf("the product must be known_affected, got %+v", v.ProductStatus)
	}
}

// A lowercase CVE id is canonicalized to the CVE-YYYY-NNNN form in both formats.
func TestVEXCanonicalizesCVE(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	fs := []finding.Finding{
		{ID: "a", EngagementID: "e1", Status: finding.StatusOpen, DedupKey: "vuln:cve-2024-12345:pkg:1.0"},
	}
	ovex := buildOpenVEX("e1", vexInputData{findings: fs}, now, "v1", "")
	if ovex.Statements[0].Vulnerability.Name != "CVE-2024-12345" {
		t.Errorf("OpenVEX CVE must be canonical uppercase, got %q", ovex.Statements[0].Vulnerability.Name)
	}
	csaf := buildCSAFVEX("e1", vexInputData{findings: fs}, now, "v1")
	if csaf.Vulnerabilities[0].CVE != "CVE-2024-12345" {
		t.Errorf("CSAF CVE must be canonical uppercase, got %q", csaf.Vulnerabilities[0].CVE)
	}
}

// Equal-rank duplicates (two not_affected findings with different justifications) must resolve
// deterministically, independent of finding read order, so the content-addressed @id is stable.
func TestVEXDedupDeterministicOnEqualRank(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	a := finding.Finding{ID: "a", EngagementID: "e1", Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-2024-0001:pkg:1.0"}
	b := finding.Finding{ID: "b", EngagementID: "e1", Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-2024-0001:pkg:1.0"}
	just := map[string]string{"a": "component_not_present", "b": "vulnerable_code_not_present"}

	forward := buildOpenVEX("e1", vexInputData{findings: []finding.Finding{a, b}, vexJust: just}, now, "v1", "")
	reverse := buildOpenVEX("e1", vexInputData{findings: []finding.Finding{b, a}, vexJust: just}, now, "v1", "")
	if forward.ID != reverse.ID {
		t.Errorf("the @id must not depend on read order: %q != %q", forward.ID, reverse.ID)
	}
	if forward.Statements[0].Justification != reverse.Statements[0].Justification {
		t.Errorf("the winning justification must be deterministic: %q vs %q",
			forward.Statements[0].Justification, reverse.Statements[0].Justification)
	}
	// The smaller justification string wins deterministically.
	if forward.Statements[0].Justification != "component_not_present" {
		t.Errorf("expected the lexicographically-smaller justification, got %q", forward.Statements[0].Justification)
	}
}

// TestVEXReachableOverridesNotAffected is the #1-bar guard for #1064: a finding whose status maps to
// not_affected (a vendor/human assertion, StatusFalsePos) must be exported as `affected` when Synapse
// independently proved it reachable, whether the proof is a winning reachability judgment (the reachable set)
// or a finding-level reachable verdict such as a runtime hit. The vendor assertion must never suppress
// Synapse's own reachable verdict on export.
func TestVEXReachableOverridesNotAffected(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	statusOf := func(doc *VEXDoc, advisory string) string {
		for _, s := range doc.Statements {
			if s.Vulnerability.Name == advisory {
				return s.Status
			}
		}
		return ""
	}

	// (1) reachable via a winning judgment (the reachable set).
	jFinding := finding.Finding{ID: "j1", EngagementID: "e1", Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-2024-1000:pkgj:1.0"}
	byJudgment := buildOpenVEX("e1", vexInputData{findings: []finding.Finding{jFinding}, reachable: map[string]bool{"j1": true}}, now, "v1", "")
	if got := statusOf(byJudgment, "CVE-2024-1000"); got != "affected" {
		t.Errorf("a Synapse-reachable finding (judgment) must export affected, not not_affected; got %q", got)
	}

	// (2) reachable via a finding-level verdict (a runtime hit sets finding.Reachability).
	rtFinding := finding.Finding{ID: "r1", EngagementID: "e1", Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-2024-1001:pkgr:1.0", Reachability: string(judgment.Reachable)}
	byField := buildOpenVEX("e1", vexInputData{findings: []finding.Finding{rtFinding}}, now, "v1", "")
	if got := statusOf(byField, "CVE-2024-1001"); got != "affected" {
		t.Errorf("a runtime-reachable finding (finding-level) must export affected, not not_affected; got %q", got)
	}

	// CSAF must reconcile identically (it shares collectVEXRecords): the reachable finding lands in the
	// product-status "known_affected" list, never "known_not_affected".
	csaf := buildCSAFVEX("e1", vexInputData{findings: []finding.Finding{jFinding}, reachable: map[string]bool{"j1": true}}, now, "v1")
	notAffected := false
	for _, v := range csaf.Vulnerabilities {
		for _, p := range v.ProductStatus.KnownNotAffected {
			_ = p
			notAffected = true
		}
	}
	if notAffected {
		t.Errorf("CSAF must not list a Synapse-reachable finding as known_not_affected: %+v", csaf.Vulnerabilities)
	}

	// (3) control: a not_affected finding with no reachable verdict still exports not_affected (the vendor
	// assertion stands when Synapse has not contradicted it).
	safe := finding.Finding{ID: "s1", EngagementID: "e1", Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-2024-1002:pkgs:1.0"}
	control := buildOpenVEX("e1", vexInputData{findings: []finding.Finding{safe}}, now, "v1", "")
	if got := statusOf(control, "CVE-2024-1002"); got != "not_affected" {
		t.Errorf("a not-contradicted not_affected assertion must stand; got %q", got)
	}
}
