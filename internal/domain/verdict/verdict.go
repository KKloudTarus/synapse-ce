// Package verdict is the shared adversarial-verdict value type + evidence bar used by BOTH
// finding (exploitation) and judgment (AI analysis). It is pure (stdlib + shared only), so
// neither aggregate imports the other for the one shared evidence-gating mechanism (R1): a
// distinct verifier seals a verdict whose score moves a claim's standing, and the same
// EvidenceThreshold gates publishability everywhere – one bar, never forked.
package verdict

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EvidenceThreshold is the minimum score (0..100) for a claim-based finding or judgment to be
// promoted/published. Shared by finding + judgment; do not fork it.
const EvidenceThreshold = 75

// DeterministicProofScore is the fixed evidence score for a judgment confirmed by a DETERMINISTIC tool
// proof (a call-graph reachability result), as opposed to a human verdict or an LLM claim.
// It is well above EvidenceThreshold because a reproducible static call-path is strong evidence, but NOT
// 100: the underlying analysis (e.g. govulncheck's VTA call graph) is over-approximate, so a "reachable"
// proof is high-confidence rather than infallible. This is the EVIDENCE/verdict score (gates Publishable);
// it is distinct from ReachabilityClaim.Confidence (the claim's own self-reported confidence field).
const DeterministicProofScore = 90

// Verdict is the outcome of an adversarial "try to refute" pass. Score is the
// verifier's confidence (0..100) that the claim SURVIVES refutation; it becomes the subject's
// evidence score. Verifier is recorded for provenance and MUST be a DISTINCT actor from the
// proposer (see SelfConfirm). Rationale is part of the sealed record.
type Verdict struct {
	Verifier  string
	Score     int
	Rationale string
}

// Validate checks a verdict is well-formed: a recorded verifier, a 0..100 score, and a rationale.
func (v Verdict) Validate() error {
	if strings.TrimSpace(v.Verifier) == "" {
		return fmt.Errorf("%w: verdict requires a verifier", shared.ErrValidation)
	}
	if v.Score < 0 || v.Score > 100 {
		return fmt.Errorf("%w: verdict score must be 0..100, got %d", shared.ErrValidation, v.Score)
	}
	if strings.TrimSpace(v.Rationale) == "" {
		return fmt.Errorf("%w: verdict requires a rationale", shared.ErrValidation)
	}
	return nil
}

// SelfConfirm reports whether a verdict would let a claim confirm itself – the verifier being the
// same actor that proposed it. A self-confirming verdict must be refused: a
// finding/judgment cannot confirm itself. An empty proposer (human/tool-sourced, no AI claim)
// never self-confirms.
func SelfConfirm(verifier, proposedBy string) bool {
	proposedBy = strings.TrimSpace(proposedBy)
	return proposedBy != "" && strings.TrimSpace(verifier) == proposedBy
}

// MeetsBar reports whether score clears the evidence threshold.
func MeetsBar(score int) bool { return score >= EvidenceThreshold }
