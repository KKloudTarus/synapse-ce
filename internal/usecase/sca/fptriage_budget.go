package sca

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AITriageBudget records bounded per-scan AI coverage. The cap is on findings, so a configured
// distinct verifier can make at most two LLM calls per attempted finding. Unattempted findings retain
// their normal gate effect. EvidenceSealFailures and EvidenceRevokedExemptions are in-memory failure
// accounting for the revocation boundary; the scan fails before ScanResult persistence, so the
// operator-visible metric is emitted separately as a stable structured event by sealEvidenceFailClosed.
type AITriageBudget struct {
	MaxFindings               int `json:"max_findings"`
	EligibleFindings          int `json:"eligible_findings"`
	AttemptedFindings         int `json:"attempted_findings"`
	SkippedFindings           int `json:"skipped_findings"`
	EvidenceSealFailures      int `json:"evidence_seal_failures,omitempty"`
	EvidenceRevokedExemptions int `json:"evidence_revoked_exemptions,omitempty"`
}

func (s *Service) runFPTriage(ctx context.Context, result *ScanResult, workspaceDir string, trace *scanDebugTrace, sastRaws []ports.SASTRawFinding) {
	if s == nil || s.fpTriager == nil || result == nil {
		return
	}
	candidates := fpTriageCandidates(result.Findings)
	if len(candidates) == 0 {
		return
	}
	maxFindings := s.fpTriageMaxFindings
	if maxFindings < 1 || maxFindings > maxFPTriageMaxFindings {
		maxFindings = defaultFPTriageMaxFindings
	}
	attempted := limitFPTriageCandidates(candidates, maxFindings)
	skipped := len(candidates) - len(attempted)
	result.AITriageBudget = &AITriageBudget{
		MaxFindings:       maxFindings,
		EligibleFindings:  len(candidates),
		AttemptedFindings: len(attempted),
		SkippedFindings:   skipped,
	}
	if skipped > 0 {
		result.SourceWarnings = append(result.SourceWarnings, fmt.Sprintf(
			"AI false-positive triage budget attempted %d of %d eligible findings; %d untriaged findings remain gating",
			len(attempted), len(candidates), skipped,
		))
	}

	counts := map[string]int{
		"candidates": len(candidates), "attempted": len(attempted),
		"skipped_budget": skipped, "max_findings": maxFindings,
	}
	tstep := -1
	if trace != nil {
		tstep = trace.start(stageFindings, "ai-fp-triage", "fp-triager", "AI false-positive triage", counts)
	}
	evidence := aiTriageEvidenceForCandidates(attempted, sastRaws)
	switch triager := s.fpTriager.(type) {
	case ports.EvidenceAwareObservableFPTriager:
		observation := triager.TriageObservedWithEvidence(ctx, attempted, workspaceDir, evidence)
		result.AITriage, result.AITriageTelemetry = observation.Critiques, &observation.Telemetry
	case ports.EvidenceAwareFPTriager:
		result.AITriage = triager.TriageWithEvidence(ctx, attempted, workspaceDir, evidence)
	case ports.ObservableFPTriager:
		observation := triager.TriageObserved(ctx, attempted, workspaceDir)
		result.AITriage, result.AITriageTelemetry = observation.Critiques, &observation.Telemetry
	default:
		result.AITriage = s.fpTriager.Triage(ctx, attempted, workspaceDir)
	}
	if result.AITriageTelemetry != nil && result.AITriageTelemetry.BudgetSkippedFindings > 0 {
		result.SourceWarnings = append(result.SourceWarnings, fmt.Sprintf("AI false-positive triage token/cost budget skipped %d attempted findings; they remain gating", result.AITriageTelemetry.BudgetSkippedFindings))
	}
	applyAIGatePolicyWithServerEvidence(result, s.evidence != nil, s.fpTriageMode, s.fpTriageIndependence, evidence)
	if result.AITriageTelemetry != nil {
		result.AITriageTelemetry.GateExemptions = len(result.AIGateExemptKeys())
		s.emitAITriageTelemetry(ctx, result)
	}
	if trace != nil {
		trace.succeed(tstep, "AI false-positive triage", map[string]int{
			"candidates":      len(candidates),
			"attempted":       len(attempted),
			"skipped_budget":  skipped,
			"max_findings":    maxFindings,
			"critiqued":       len(result.AITriage),
			"suspected_fp":    len(result.SuspectedFPKeys()),
			"gate_exempt":     len(result.AIGateExemptKeys()),
			"would_exempt":    len(result.AIWouldGateExemptKeys()),
			"review_required": len(result.AIReviewRequiredKeys()),
		})
	}
}

// limitFPTriageCandidates returns at most maxFindings without mutating the caller's slice. When a cap
// applies, policy-exemptible findings are considered first, then higher severity/risk, with stable
// finding identity tie-breakers. Selection therefore cannot drift with scanner completion order.
func limitFPTriageCandidates(candidates []finding.Finding, maxFindings int) []finding.Finding {
	if maxFindings < 1 || maxFindings > maxFPTriageMaxFindings {
		maxFindings = defaultFPTriageMaxFindings
	}
	if len(candidates) <= maxFindings {
		return candidates
	}
	ranked := append([]finding.Finding(nil), candidates...)
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		aMayExempt := humanReviewFloor(a) == ""
		bMayExempt := humanReviewFloor(b) == ""
		if aMayExempt != bMayExempt {
			return aMayExempt
		}
		if ar, br := shared.SeverityRank(a.Severity), shared.SeverityRank(b.Severity); ar != br {
			return ar > br
		}
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		if ak, bk := strings.TrimSpace(a.DedupKey), strings.TrimSpace(b.DedupKey); ak != bk {
			return ak < bk
		}
		return a.ID.String() < b.ID.String()
	})
	return ranked[:maxFindings]
}
