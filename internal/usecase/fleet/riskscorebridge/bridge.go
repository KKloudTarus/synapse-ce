// Package riskscorebridge provides honest-abstaining factor sources for the tri-score assembler
// (riskscoreuc) at the composition root. The assembler REQUIRES a non-nil ExposureAssessor,
// BehaviorAssessor and CoverageSource; where a producer is not yet integrated, an abstaining source keeps
// the seam live and coverage-honest — an abstaining factor contributes 0 to Risk and carries its reason
// into the CoverageVector, so a not-yet-wired factor lowers coverage/confidence and NEVER fabricates risk.
//
// This lets the deterministic Scorer run in production on the factors that ARE wired while the remaining
// producers are swapped in as isolated follow-ups. Exposure is wired via NewExposure (over exposureuc) and
// Coverage via NewCoverage (over the coverage-window store); Behavior still abstains until its producer (a
// baselineuc per-asset read path) is integrated. Each swap replaces one Abstaining* here with a real bridge.
package riskscorebridge

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/exposureuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/riskscoreuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ExposureProducer is the exposureuc surface the real Exposure bridge adapts. exposureuc.Service
// satisfies it. Kept narrow so the bridge depends on the producer's behavior, not its concrete type.
type ExposureProducer interface {
	Assess(ctx context.Context, assetID shared.ID) (exposureuc.Assessment, error)
}

type exposureBridge struct{ producer ExposureProducer }

// NewExposure bridges the real exposureuc producer (X5) to the assembler's ExposureAssessor port,
// mapping exposureuc.Assessment (Exposure/Scoreable/Reasons) to the assembler's FactorInput. A producer
// error propagates; an abstain (Scoreable=false) flows through unchanged, so the assembler keeps its
// coverage-honest handling.
func NewExposure(producer ExposureProducer) riskscoreuc.ExposureAssessor {
	return exposureBridge{producer: producer}
}

func (b exposureBridge) ExposureFor(ctx context.Context, assetID shared.ID) (riskscoreuc.FactorInput, error) {
	a, err := b.producer.Assess(ctx, assetID)
	if err != nil {
		return riskscoreuc.FactorInput{}, err
	}
	return riskscoreuc.FactorInput{Score: a.Exposure, Scoreable: a.Scoreable, Reasons: a.Reasons}, nil
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

// CoverageWindowReader lists an asset's composed coverage windows (tenant-scoped via ctx).
// ports.CoverageWindowStore satisfies it.
type CoverageWindowReader interface {
	ListCoverageWindows(ctx context.Context, q ports.CoverageWindowQuery) ([]sensorstate.CoverageWindow, error)
}

type coverageBridge struct{ reader CoverageWindowReader }

// NewCoverage bridges the real coverage-window store to the assembler's CoverageSource port: it returns
// the per-class coverage of the asset's MOST RECENT composed window (windows are listed newest-first).
// When the asset has no window yet, it returns nil — the assembler then reads every class as a gap, the
// honest state when no coverage has been observed. This feeds the CoverageVector only, never Risk.
func NewCoverage(reader CoverageWindowReader) riskscoreuc.CoverageSource {
	return coverageBridge{reader: reader}
}

func (b coverageBridge) ClassCoverageForAsset(ctx context.Context, assetID shared.ID) ([]detection.ClassCoverage, error) {
	windows, err := b.reader.ListCoverageWindows(ctx, ports.CoverageWindowQuery{AssetID: assetID, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(windows) == 0 {
		return nil, nil
	}
	return windows[0].States, nil
}
