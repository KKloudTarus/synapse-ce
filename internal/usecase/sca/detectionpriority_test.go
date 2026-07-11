package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestApplyDetectionPriority(t *testing.T) {
	res := &ScanResult{
		Findings: []finding.Finding{
			{ID: "single", Title: "single-source CVE", DedupKey: "vuln:CVE-1:a:1", Severity: shared.SeverityHigh, Sources: []string{"osv"}},
			{ID: "multi", Title: "corroborated CVE", DedupKey: "vuln:CVE-2:b:1", Severity: shared.SeverityHigh, Sources: []string{"osv", "grype"}},
			{ID: "kev", Title: "KEV CVE", DedupKey: "vuln:CVE-3:c:1", Severity: shared.SeverityHigh, Sources: []string{"osv"}, KEV: true},
			{ID: "sast", Title: "SAST hit", DedupKey: "sast:rule:file:1", Severity: shared.SeverityHigh, Sources: []string{"synapse-pattern-sast"}, Kind: finding.KindSAST},
		},
	}
	applyDetectionPriority(res, DetectionPrecise)

	// CRITICAL: nothing is removed – all findings stay reported/sealed.
	if len(res.Findings) != 4 {
		t.Fatalf("detection-priority must NOT remove findings, got %d", len(res.Findings))
	}
	// Only the single-source, non-KEV VULN finding is quarantined.
	if len(res.NeedsVerification) != 1 || res.NeedsVerification[0].DedupKey != "vuln:CVE-1:a:1" {
		t.Fatalf("only the single-source non-KEV vuln must be quarantined, got %+v", res.NeedsVerification)
	}
	keys := res.NeedsVerifyKeys()
	if !keys["vuln:CVE-1:a:1"] {
		t.Error("the single-source vuln must be gate-exempt")
	}
	// Corroborated (multi-source), KEV, and deterministic first-party (SAST) stay actionable.
	for _, k := range []string{"vuln:CVE-2:b:1", "vuln:CVE-3:c:1", "sast:rule:file:1"} {
		if keys[k] {
			t.Errorf("%s must stay actionable (corroborated/KEV/first-party), not quarantined", k)
		}
	}
}

func TestApplyDetectionPriorityComprehensiveIsNoop(t *testing.T) {
	res := &ScanResult{Findings: []finding.Finding{{ID: "x", DedupKey: "vuln:CVE-1:a:1", Sources: []string{"osv"}}}}
	applyDetectionPriority(res, DetectionComprehensive)
	if len(res.NeedsVerification) != 0 {
		t.Error("comprehensive mode must quarantine nothing")
	}
	applyDetectionPriority(res, "") // empty defaults to comprehensive behavior (no-op)
	if len(res.NeedsVerification) != 0 {
		t.Error("empty priority must behave as comprehensive (no-op)")
	}
}

func TestNormalizeScanOptionsDetectionPriority(t *testing.T) {
	// Empty defaults to comprehensive.
	if o, err := normalizeScanOptions(ScanOptions{Mode: "full"}); err != nil || o.DetectionPriority != DetectionComprehensive {
		t.Errorf("empty priority must default to comprehensive, got %q err=%v", o.DetectionPriority, err)
	}
	// Explicit precise is preserved (case-insensitive).
	if o, err := normalizeScanOptions(ScanOptions{Mode: "full", DetectionPriority: "PRECISE"}); err != nil || o.DetectionPriority != DetectionPrecise {
		t.Errorf("precise must normalize, got %q err=%v", o.DetectionPriority, err)
	}
	// An unknown priority is rejected.
	if _, err := normalizeScanOptions(ScanOptions{Mode: "full", DetectionPriority: "bogus"}); err == nil {
		t.Error("an unknown detection priority must be rejected")
	}
}
