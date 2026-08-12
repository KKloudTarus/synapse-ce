package sca

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type combinedTriageProbe struct {
	legacy, observed, evidence, combined int
	seen map[string][]ports.AITriageEvidenceToken
}
func (p *combinedTriageProbe) Triage(context.Context, []finding.Finding, string) []ports.AICritique { p.legacy++; return nil }
func (p *combinedTriageProbe) TriageObserved(context.Context, []finding.Finding, string) ports.FPTriageObservedResult { p.observed++; return ports.FPTriageObservedResult{} }
func (p *combinedTriageProbe) TriageWithEvidence(_ context.Context, _ []finding.Finding, _ string, e map[string][]ports.AITriageEvidenceToken) []ports.AICritique { p.evidence++; p.seen=e; return nil }
func (p *combinedTriageProbe) TriageObservedWithEvidence(_ context.Context, _ []finding.Finding, _ string, e map[string][]ports.AITriageEvidenceToken) ports.FPTriageObservedResult { p.combined++; p.seen=e; return ports.FPTriageObservedResult{Telemetry: ports.FPTriageTelemetry{RequestCount: 7}} }

func TestRunFPTriagePrefersEvidenceAwareObservableSeam(t *testing.T) {
	probe := &combinedTriageProbe{}
	s := &Service{fpTriager: probe, fpTriageMaxFindings: 10}
	f := finding.Finding{ID: "finding-1", DedupKey: "sast:test", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: "production", Severity: "medium", CWE: "CWE-79", Title: "x"}
	result := &ScanResult{Findings: []finding.Finding{f}}
	raw := ports.SASTRawFinding{RuleID: "test", CWE: "CWE-79", Severity: "medium"}
	s.runFPTriage(context.Background(), result, "", nil, []ports.SASTRawFinding{raw})
	if probe.combined != 1 || probe.legacy != 0 || probe.observed != 0 || probe.evidence != 0 {
		t.Fatalf("dispatch legacy=%d observed=%d evidence=%d combined=%d", probe.legacy, probe.observed, probe.evidence, probe.combined)
	}
	if result.AITriageTelemetry == nil || result.AITriageTelemetry.RequestCount != 7 || len(probe.seen) != 1 {
		t.Fatalf("telemetry=%+v evidence=%+v", result.AITriageTelemetry, probe.seen)
	}
}
