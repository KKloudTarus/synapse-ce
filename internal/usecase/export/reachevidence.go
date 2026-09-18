package export

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

// ReachabilityLabel is the closed, user-visible reachability vocabulary rendered as a tagged evidence item
// (EPIC #1042, 0.2). It is DERIVED at the surface from a finding's reachability judgments; it is not a
// domain verdict and does not change the ReachabilityState enum (which stays reachable|not_reachable|
// unknown). The wire values match the reachbench label vocabulary so the benchmark and the public export
// speak one contract, and the OpenAPI enum is the authoritative public schema.
type ReachabilityLabel string

const (
	// LabelReachable: a PUBLISHABLE reachable judgment (any tier) is the winning claim. The vulnerable code
	// is reached; the call/exploit path is carried alongside.
	LabelReachable ReachabilityLabel = "reachable"
	// LabelConditionallyReachable: reachable only under a precondition (a taint label / guard). Reserved for
	// the conditional-reachability engine; not emitted until that lands.
	LabelConditionallyReachable ReachabilityLabel = "conditionally_reachable"
	// LabelPresentUnreached: a SOUND proof of non-reachability (SuppressesFinding). The vulnerable code is
	// present in a matched dependency but proven not reached.
	LabelPresentUnreached ReachabilityLabel = "present_unreached"
	// LabelNoAnalysis: no conclusive reachability analysis for this finding, either because no reachability
	// judgment exists or the strongest one is inconclusive (unknown / unproven). Distinct from
	// present_unreached: absence of analysis is never reported as a proven-unreached result.
	LabelNoAnalysis ReachabilityLabel = "no_analysis"
)

// ReachabilityEvidence is the tagged evidence item a finding renders for its reachability posture, adopting
// the Snyk evidence[] contract (source-tagged evidence beside the dependency path). Source is always
// "reachability"; Label is the derived four-state label; Tier is the proving tier when a judgment decided
// it; Path is the call/exploit path from the winning claim (empty when none / not reachable).
type ReachabilityEvidence struct {
	Source string                    `json:"source"` // always "reachability"
	Label  ReachabilityLabel         `json:"label"`
	Tier   judgment.ReachabilityTier `json:"tier,omitempty"`
	Path   []string                  `json:"path,omitempty"`
}

// DeriveReachabilityEvidence derives a finding's reachability evidence from its PUBLISHABLE, finding-scoped
// reachability judgments (the same publishability gate the VEX path uses). It selects the winning claim with
// the shared state-aware ordering (judgment.ReachabilityClaim.Supersedes, EPIC #1042 A-CORE), so an unproven
// negative never shadows a reachable, then maps it to a derived label:
//
//   - a winning REACHABLE claim -> reachable (with its call path);
//   - a winning proven not_reachable (SuppressesFinding) -> present_unreached;
//   - a winning inconclusive claim, or NO reachability judgment at all -> no_analysis.
//
// It never mints conditionally_reachable (reserved for the conditional engine). It ALWAYS returns a non-nil
// evidence item so every finding carries an explicit reachability posture (no_analysis when nothing
// conclusive ran), never a silently-absent one. Deriving at the surface keeps the domain verdict enum
// unchanged.
func DeriveReachabilityEvidence(judgments []judgment.Judgment, findingID string) *ReachabilityEvidence {
	var winner judgment.ReachabilityClaim
	have := false
	for _, j := range judgments {
		if !j.Publishable() || j.Capability != judgment.CapReachability || j.SubjectKind != judgment.SubjectFinding {
			continue
		}
		if j.SubjectID.String() != findingID {
			continue
		}
		rc, ok := j.Claim.(judgment.ReachabilityClaim)
		if !ok {
			continue
		}
		if !have || rc.Supersedes(winner) {
			winner, have = rc, true
		}
	}
	if !have {
		return &ReachabilityEvidence{Source: "reachability", Label: LabelNoAnalysis}
	}
	switch {
	case winner.Reachable == judgment.Reachable:
		return &ReachabilityEvidence{Source: "reachability", Label: LabelReachable, Tier: winner.Tier, Path: winner.Path}
	case winner.Reachable == judgment.ConditionallyReachable:
		// Reached under an unproven precondition: exploitable-under-condition, never a suppression.
		return &ReachabilityEvidence{Source: "reachability", Label: LabelConditionallyReachable, Tier: winner.Tier, Path: winner.Path}
	case winner.SuppressesFinding():
		return &ReachabilityEvidence{Source: "reachability", Label: LabelPresentUnreached, Tier: winner.Tier}
	default:
		// A reachability judgment exists but is inconclusive (unknown, or an unproven negative that cannot
		// soundly claim present_unreached): report no_analysis rather than overstate a proven-unreached.
		return &ReachabilityEvidence{Source: "reachability", Label: LabelNoAnalysis}
	}
}
