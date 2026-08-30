// Package riskscorebridge provides honest-abstaining factor sources for the tri-score assembler
// (riskscoreuc) at the composition root. The assembler REQUIRES a non-nil ExposureAssessor,
// BehaviorAssessor and CoverageSource; where a producer is not yet integrated, an abstaining source keeps
// the seam live and coverage-honest — an abstaining factor contributes 0 to Risk and carries its reason
// into the CoverageVector, so a not-yet-wired factor lowers coverage/confidence and NEVER fabricates risk.
//
// This lets the deterministic Scorer run in production on the factors that ARE wired (Threat, from the
// incident's own correlated severity, which DefaultPolicy treats as dominant) while the remaining
// producers are swapped in as isolated follow-ups: Exposure → exposureuc, Behavior → baselineuc,
// Coverage → coveragewindow. Each swap replaces one Abstaining* here with the real bridge.
package riskscorebridge

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/riskscoreuc"
)

// abstainingExposure always abstains — used until exposureuc is wired at the composition root.
type abstainingExposure struct{ reason string }

// AbstainingExposure returns an ExposureAssessor that always abstains with a fixed reason.
func AbstainingExposure(reason string) riskscoreuc.ExposureAssessor {
	return abstainingExposure{reason: reason}
}

func (a abstainingExposure) ExposureFor(context.Context, shared.ID) (riskscoreuc.FactorInput, error) {
	return riskscoreuc.FactorInput{Scoreable: false, Reasons: []string{a.reason}}, nil
}

// abstainingBehavior always abstains — used until baselineuc exposes a per-asset behavior read path.
type abstainingBehavior struct{ reason string }

// AbstainingBehavior returns a BehaviorAssessor that always abstains with a fixed reason.
func AbstainingBehavior(reason string) riskscoreuc.BehaviorAssessor {
	return abstainingBehavior{reason: reason}
}

func (a abstainingBehavior) BehaviorFor(context.Context, shared.ID) (riskscoreuc.FactorInput, error) {
	return riskscoreuc.FactorInput{Scoreable: false, Reasons: []string{a.reason}}, nil
}

// abstainingCoverage reports no per-class detection coverage — used until coveragewindow is bridged. The
// assembler then treats every class as an observation gap, which is the honest state when detection
// coverage is not yet wired.
type abstainingCoverage struct{}

// AbstainingCoverage returns a CoverageSource that yields no class coverage (every class reads as a gap).
func AbstainingCoverage() riskscoreuc.CoverageSource { return abstainingCoverage{} }

func (abstainingCoverage) ClassCoverageForAsset(context.Context, shared.ID) ([]detection.ClassCoverage, error) {
	return nil, nil
}
