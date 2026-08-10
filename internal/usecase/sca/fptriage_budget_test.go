package sca

import (
	"context"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recordingFPTriager struct {
	candidates []finding.Finding
}

func (r *recordingFPTriager) Triage(_ context.Context, candidates []finding.Finding, _ string) []ports.AICritique {
	r.candidates = append([]finding.Finding(nil), candidates...)
	out := make([]ports.AICritique, len(candidates))
	for i, item := range candidates {
		out[i] = ports.AICritique{
			FindingID: item.ID.String(), DedupKey: item.DedupKey,
			Verdict: "sound", Driver: "attacker_controlled", Confidence: 80,
			ProposerModel: "proposer", PromptVersion: "test",
		}
	}
	return out
}

func budgetFinding(key string, severity shared.Severity, risk float64, cwe string) finding.Finding {
	return finding.Finding{
		ID: shared.ID("id-" + key), DedupKey: key, Title: key,
		Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction,
		Severity: severity, RiskScore: risk, CWE: cwe,
	}
}

func candidateKeys(items []finding.Finding) []string {
	keys := make([]string, len(items))
	for i := range items {
		keys[i] = items[i].DedupKey
	}
	return keys
}

func TestRunFPTriageHardCapsAndSurfacesSkippedFindings(t *testing.T) {
	triager := &recordingFPTriager{}
	service := &Service{fpTriager: triager, fpTriageMaxFindings: 2}
	result := &ScanResult{Findings: []finding.Finding{
		budgetFinding("protected-high", shared.SeverityHigh, 99, "CWE-327"),
		budgetFinding("safe-lower-risk", shared.SeverityMedium, 20, "CWE-327"),
		budgetFinding("protected-cwe", shared.SeverityMedium, 100, "CWE-89"),
		budgetFinding("safe-higher-risk", shared.SeverityMedium, 90, "CWE-327"),
	}}
	trace := newScanDebugTrace(nil)

	service.runFPTriage(context.Background(), result, "workspace", trace)

	if len(result.Findings) != 4 {
		t.Fatalf("budget must retain every finding, got %d", len(result.Findings))
	}
	wantAttempted := []string{"safe-higher-risk", "safe-lower-risk"}
	if got := candidateKeys(triager.candidates); !reflect.DeepEqual(got, wantAttempted) {
		t.Fatalf("attempted candidates = %v, want %v", got, wantAttempted)
	}
	wantBudget := &AITriageBudget{MaxFindings: 2, EligibleFindings: 4, AttemptedFindings: 2, SkippedFindings: 2}
	if !reflect.DeepEqual(result.AITriageBudget, wantBudget) {
		t.Fatalf("AI triage budget = %+v, want %+v", result.AITriageBudget, wantBudget)
	}
	wantWarning := "AI false-positive triage budget attempted 2 of 4 eligible findings; 2 untriaged findings remain gating"
	if len(result.SourceWarnings) != 1 || result.SourceWarnings[0] != wantWarning {
		t.Fatalf("budget warning = %v, want %q", result.SourceWarnings, wantWarning)
	}
	if got := result.AIGateExemptKeys(); len(got) != 0 {
		t.Fatalf("sound or untriaged findings unexpectedly became gate-exempt: %v", got)
	}
	events := trace.snapshot()
	if len(events) != 1 || events[0].Counts["attempted"] != 2 || events[0].Counts["skipped_budget"] != 2 || events[0].Counts["max_findings"] != 2 {
		t.Fatalf("budget counts not visible in debug trace: %+v", events)
	}
}

func TestLimitFPTriageCandidatesIsOrderIndependent(t *testing.T) {
	input := []finding.Finding{
		budgetFinding("z", shared.SeverityMedium, 10, "CWE-327"),
		budgetFinding("protected", shared.SeverityHigh, 100, "CWE-327"),
		budgetFinding("a", shared.SeverityMedium, 10, "CWE-327"),
	}
	reversed := []finding.Finding{input[2], input[1], input[0]}
	want := []string{"a", "z"}
	if got := candidateKeys(limitFPTriageCandidates(input, 2)); !reflect.DeepEqual(got, want) {
		t.Fatalf("selection = %v, want %v", got, want)
	}
	if got := candidateKeys(limitFPTriageCandidates(reversed, 2)); !reflect.DeepEqual(got, want) {
		t.Fatalf("reversed selection = %v, want %v", got, want)
	}
	if got := candidateKeys(input); !reflect.DeepEqual(got, []string{"z", "protected", "a"}) {
		t.Fatalf("selection mutated caller input: %v", got)
	}
}

func TestSetFPTriageMaxFindingsRejectsUnboundedZero(t *testing.T) {
	service := &Service{}
	for _, value := range []int{0, -1, maxFPTriageMaxFindings + 1} {
		service.SetFPTriageMaxFindings(value)
		if service.fpTriageMaxFindings != defaultFPTriageMaxFindings {
			t.Errorf("invalid cap %d = %d, want finite default %d", value, service.fpTriageMaxFindings, defaultFPTriageMaxFindings)
		}
	}
}
