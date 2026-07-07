package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
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
