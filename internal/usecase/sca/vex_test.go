package sca

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ignore"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestApplyVEX(t *testing.T) {
	v1 := vulnerability.Vulnerability{ID: "CVE-2024-1", Component: "lodash", Version: "4.17.21"}
	v2 := vulnerability.Vulnerability{ID: "CVE-2024-2", Component: "express", Version: "4.18.0"}
	res := &ScanResult{
		Vulnerabilities: []vulnerability.Vulnerability{v1, v2},
		Findings: []finding.Finding{
			{ID: "f1", Title: "lodash CVE-2024-1", DedupKey: vulnDedupKey(v1)},
			{ID: "f2", Title: "express CVE-2024-2", DedupKey: vulnDedupKey(v2)},
		},
	}
	doc, err := vex.Parse([]byte(`{
      "@context":"https://openvex.dev/ns/v0.2.0",
      "statements":[
        {"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/lodash@4.17.21"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"},
        {"vulnerability":{"name":"CVE-2024-2"},"products":[{"@id":"pkg:npm/express@4.18.0"}],"status":"affected"}
      ]}`))
	if err != nil {
		t.Fatal(err)
	}
	applyVEX(res, doc)

	// not_affected → f1 accepted; affected → f2 stays actionable.
	if len(res.Findings) != 2 {
		t.Fatalf("VEX must NOT remove findings (retain-and-mark), got %d", len(res.Findings))
	}
	if len(res.SuppressedFindings) != 1 || res.SuppressedFindings[0].DedupKey != vulnDedupKey(v1) {
		t.Fatalf("want exactly f1 accepted (not_affected), got %+v", res.SuppressedFindings)
	}
	sf := res.SuppressedFindings[0]
	if sf.RuleID != "CVE-2024-1" || sf.Reason != "VEX not_affected: vulnerable_code_not_in_execute_path" {
		t.Errorf("accepted-risk annotation must carry the CVE + VEX justification, got %+v", sf)
	}
	// f2 (affected) is NOT gate-exempt.
	if res.SuppressedKeys()[vulnDedupKey(v2)] {
		t.Error("an 'affected' statement must not exempt a finding")
	}
}

// TestApplyVEXDoesNotExemptReachableFinding is the in-scan twin of the control-plane #1-bar guard: an
// in-repo not_affected must NOT exempt the CI gate for a finding Synapse proved reachable. The finding stays
// on the gate and the conflict is surfaced. A `fixed` statement (remediation, orthogonal to reachability)
// still exempts even a reachable finding.
func TestApplyVEXDoesNotExemptReachableFinding(t *testing.T) {
	v1 := vulnerability.Vulnerability{ID: "CVE-2024-1", Component: "lodash", Version: "4.17.21"}
	v2 := vulnerability.Vulnerability{ID: "CVE-2024-2", Component: "express", Version: "4.18.0"}
	res := &ScanResult{
		Vulnerabilities: []vulnerability.Vulnerability{v1, v2},
		Findings: []finding.Finding{
			// f1 is proven reachable (finding-level verdict); f2 is not.
			{ID: "f1", DedupKey: vulnDedupKey(v1), Reachability: "reachable"},
			{ID: "f2", DedupKey: vulnDedupKey(v2), Reachability: "high"},
		},
	}
	doc, err := vex.Parse([]byte(`{
      "@context":"https://openvex.dev/ns/v0.2.0",
      "statements":[
        {"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/lodash@4.17.21"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"},
        {"vulnerability":{"name":"CVE-2024-2"},"products":[{"@id":"pkg:npm/express@4.18.0"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}
      ]}`))
	if err != nil {
		t.Fatal(err)
	}
	applyVEX(res, doc)

	// f1 (reachable) must NOT be gate-exempted; f2 (not reachable) must be.
	sup := res.SuppressedKeys()
	if sup[vulnDedupKey(v1)] {
		t.Error("a not_affected must NOT exempt a Synapse-reachable finding from the gate")
	}
	if !sup[vulnDedupKey(v2)] {
		t.Error("a not_affected must still exempt a finding Synapse did not prove reachable")
	}
	if len(res.SourceWarnings) != 1 {
		t.Errorf("the un-applied not_affected conflict must be surfaced as a source warning, got %v", res.SourceWarnings)
	}
}

// TestApplyVEXFixedStillExemptsReachable confirms a `fixed` statement (remediation) exempts even a reachable
// finding: reachability contradicts "not exploitable" (not_affected), not "remediated" (fixed).
func TestApplyVEXFixedStillExemptsReachable(t *testing.T) {
	v1 := vulnerability.Vulnerability{ID: "CVE-2024-1", Component: "lodash", Version: "4.17.21"}
	res := &ScanResult{
		Vulnerabilities: []vulnerability.Vulnerability{v1},
		Findings:        []finding.Finding{{ID: "f1", DedupKey: vulnDedupKey(v1), Reachability: "reachable"}},
	}
	doc, err := vex.Parse([]byte(`{
      "@context":"https://openvex.dev/ns/v0.2.0",
      "statements":[
        {"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/lodash@4.17.21"}],"status":"fixed"}
      ]}`))
	if err != nil {
		t.Fatal(err)
	}
	applyVEX(res, doc)
	if !res.SuppressedKeys()[vulnDedupKey(v1)] {
		t.Error("a 'fixed' statement must still exempt a reachable finding (remediation is orthogonal to reachability)")
	}
}

func TestApplyVEXDoesNotDoubleAnnotate(t *testing.T) {
	v1 := vulnerability.Vulnerability{ID: "CVE-2024-1", Component: "lodash", Version: "4.17.21"}
	res := &ScanResult{
		Vulnerabilities:    []vulnerability.Vulnerability{v1},
		Findings:           []finding.Finding{{ID: "f1", DedupKey: vulnDedupKey(v1)}},
		SuppressedFindings: []SuppressedFinding{{DedupKey: vulnDedupKey(v1), RuleID: "CVE-2024-1", Reason: "already accepted via .synapseignore"}},
	}
	doc, _ := vex.Parse([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/lodash"}],"status":"not_affected"}]}`))
	applyVEX(res, doc)
	if len(res.SuppressedFindings) != 1 {
		t.Errorf("a finding already accepted must not be annotated twice, got %d", len(res.SuppressedFindings))
	}
}

// TestApplyVEXMatchesAlias: an in-repo statement naming CVE-2024-1001 targets the finding reported under
// GHSA-aaaa-bbbb-cccc, whose only CVE it is, and nothing else.
func TestApplyVEXMatchesAlias(t *testing.T) {
	v := vulnerability.Vulnerability{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2024-1001", "PYSEC-2024-1"}, Component: "pillow", Version: "10.0.0"}
	other := vulnerability.Vulnerability{ID: "CVE-2023-9999", Component: "pillow", Version: "10.0.0"}
	res := &ScanResult{
		Vulnerabilities: []vulnerability.Vulnerability{v, other},
		Findings: []finding.Finding{
			{ID: "f1", Title: "pillow", DedupKey: vulnDedupKey(v)},
			{ID: "f2", Title: "pillow other", DedupKey: vulnDedupKey(other)},
		},
	}
	doc, err := vex.Parse([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
        {"vulnerability":{"name":"CVE-2024-1001"},"products":[{"@id":"pkg:pypi/pillow@10.0.0"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	applyVEX(res, doc)
	if len(res.SuppressedFindings) != 1 || res.SuppressedFindings[0].DedupKey != vulnDedupKey(v) {
		t.Fatalf("want only the aliased finding accepted, got %+v", res.SuppressedFindings)
	}
}

// TestApplyVEXDoesNotBridgeFollowUpAdvisory: path-to-regexp 0.1.12 fixes CVE-2024-45296 but still has
// CVE-2026-4867, and both are aliases of GHSA-37ch-88jc-xwx2. A true "fixed" statement for the older CVE must
// leave the finding on the gate.
func TestApplyVEXDoesNotBridgeFollowUpAdvisory(t *testing.T) {
	raws := []vulnerability.RawFinding{{
		Source: "osv", AdvisoryID: vulnerability.PreferCVE("GHSA-37ch-88jc-xwx2", []string{"CVE-2024-45296", "CVE-2026-4867"}),
		Aliases:   []string{"GHSA-37ch-88jc-xwx2", "CVE-2024-45296", "CVE-2026-4867"},
		Component: "path-to-regexp", Version: "0.1.12",
	}}
	vulns := vulnerability.Correlate(raws)
	res := &ScanResult{Vulnerabilities: vulns, Findings: []finding.Finding{{ID: "f1", Title: "path-to-regexp", DedupKey: vulnDedupKey(vulns[0])}}}
	doc, err := vex.Parse([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
        {"vulnerability":{"name":"CVE-2024-45296"},"products":[{"@id":"pkg:npm/path-to-regexp@0.1.12"}],"status":"fixed"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	applyVEX(res, doc)
	applySuppressions(res, ignore.Parse([]byte("CVE-2024-45296 # fixed in 0.1.12\n")), time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC))
	if len(res.SuppressedFindings) != 0 {
		t.Fatalf("a statement about the superseded CVE must not exempt the follow-up advisory: %+v", res.SuppressedFindings)
	}
}
