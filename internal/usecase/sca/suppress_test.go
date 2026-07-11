package sca

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ignore"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestApplySuppressions(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	v := vulnerability.Vulnerability{ID: "CVE-2023-1", Component: "lodash", Version: "4.0.0"}
	res := &ScanResult{
		Vulnerabilities: []vulnerability.Vulnerability{v},
		Findings: []finding.Finding{
			{ID: "f1", Title: "lodash CVE-2023-1", DedupKey: vulnDedupKey(v), Severity: shared.SeverityHigh},
			{ID: "f2", Title: "keep me", DedupKey: "vuln:CVE-2023-2:x:1", Severity: shared.SeverityHigh},
			{ID: "f3", Title: "pinned by dedup key", DedupKey: "secret:rule:file:9"},
		},
	}
	// Accept f1 by its CVE, f3 by its exact dedup key; declare an expired rule that matches nothing.
	set := ignore.Parse([]byte("CVE-2023-1 # accepted, not exploitable\nsecret:rule:file:9 exp:2027-01-01 # pinned\nGHSA-lapsed exp:2026-01-01\n"))
	applySuppressions(res, set, now)

	// CRITICAL governance property: nothing is removed – all findings stay in the actionable/reported set.
	if len(res.Findings) != 3 {
		t.Fatalf("suppression must NOT remove findings (they stay reported + sealed); got %d", len(res.Findings))
	}
	if len(res.SuppressedFindings) != 2 {
		t.Fatalf("want 2 accepted-risk annotations (f1 by CVE, f3 by dedup key), got %d: %+v", len(res.SuppressedFindings), res.SuppressedFindings)
	}
	found := false
	for _, s := range res.SuppressedFindings {
		if s.DedupKey == vulnDedupKey(v) && s.RuleID == "CVE-2023-1" && s.Reason == "accepted, not exploitable" {
			found = true
		}
	}
	if !found {
		t.Error("an accepted-risk annotation must carry the finding key + rule id + reason")
	}
	// The accepted keys are exactly the gate-exemption set.
	keys := res.SuppressedKeys()
	if !keys[vulnDedupKey(v)] || !keys["secret:rule:file:9"] || keys["vuln:CVE-2023-2:x:1"] {
		t.Errorf("SuppressedKeys must be exactly the accepted set, got %+v", keys)
	}
	// An expired rule is surfaced even though it accepted nothing, so the operator knows to refresh it.
	if len(res.ExpiredSuppressions) != 1 || res.ExpiredSuppressions[0] != "GHSA-lapsed" {
		t.Errorf("expired rule must be surfaced, got %+v", res.ExpiredSuppressions)
	}
}

func TestApplySuppressionsMalformedExpiryIsFailSafe(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	v := vulnerability.Vulnerability{ID: "CVE-2023-1", Component: "lodash", Version: "4.0.0"}
	res := &ScanResult{
		Vulnerabilities: []vulnerability.Vulnerability{v},
		Findings:        []finding.Finding{{ID: "f1", DedupKey: vulnDedupKey(v)}},
	}
	// A typo'd expiry must NOT become a permanent acceptance: the rule does not suppress and is surfaced.
	applySuppressions(res, ignore.Parse([]byte("CVE-2023-1 exp:2026-31-12 # typo month/day\n")), now)
	if len(res.SuppressedFindings) != 0 {
		t.Error("a malformed-expiry rule must NOT accept anything (fail-safe)")
	}
	if len(res.MalformedSuppressions) != 1 || res.MalformedSuppressions[0] != "CVE-2023-1" {
		t.Errorf("a malformed rule must be surfaced, got %+v", res.MalformedSuppressions)
	}
}

func TestApplySuppressionsEmptyPolicyIsNoop(t *testing.T) {
	res := &ScanResult{Findings: []finding.Finding{{ID: "f1", DedupKey: "x"}}}
	applySuppressions(res, nil, time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC))
	if len(res.Findings) != 1 || len(res.SuppressedFindings) != 0 {
		t.Errorf("an empty policy must be a no-op, got findings=%d suppressed=%d", len(res.Findings), len(res.SuppressedFindings))
	}
}

func TestApplySuppressionsExpiredDoesNotSuppress(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	v := vulnerability.Vulnerability{ID: "CVE-2023-1", Component: "lodash", Version: "4.0.0"}
	res := &ScanResult{
		Vulnerabilities: []vulnerability.Vulnerability{v},
		Findings:        []finding.Finding{{ID: "f1", DedupKey: vulnDedupKey(v)}},
	}
	// The rule for this CVE has expired → the finding must re-surface (stay actionable), never suppressed.
	applySuppressions(res, ignore.Parse([]byte("CVE-2023-1 exp:2026-01-01 # lapsed\n")), now)
	if len(res.Findings) != 1 || len(res.SuppressedFindings) != 0 {
		t.Errorf("an expired rule must not suppress; finding must re-surface. findings=%d suppressed=%d", len(res.Findings), len(res.SuppressedFindings))
	}
}
