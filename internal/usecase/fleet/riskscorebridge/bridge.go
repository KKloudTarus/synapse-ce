// Package riskscorebridge adapts the tri-score assembler's (riskscoreuc) three consumer-side factor ports
// to their real producers. All three factors are now wired: Exposure via NewExposure (exposureuc, X5),
// Behavior via NewBehavior (behaviorbaseline, D), and Coverage via NewCoverage (the coverage-window store).
// Each bridge maps its producer's coverage-honest result to the assembler's FactorInput — a producer error
// propagates, and an abstain (Scoreable=false, e.g. a cold-starting baseline) flows through unchanged so
// the assembler keeps its discipline: an abstaining factor contributes 0 to Risk and its reason lowers
// Coverage/confidence in the CoverageVector, NEVER fabricating risk.
package riskscorebridge

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/behaviorbaseline"
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

// BehaviorProducer is the behaviorbaseline surface the real Behavior bridge adapts. behaviorbaseline.Service
// satisfies it.
type BehaviorProducer interface {
	BehaviorFor(ctx context.Context, assetID shared.ID) (behaviorbaseline.Factor, error)
}

type behaviorBridge struct{ producer BehaviorProducer }

// NewBehavior bridges the real behaviorbaseline producer (D) to the assembler's BehaviorAssessor port,
// mapping its Factor to FactorInput. A producer error propagates; an abstain (Scoreable=false, e.g. a
// baseline still cold-starting) flows through unchanged.
func NewBehavior(producer BehaviorProducer) riskscoreuc.BehaviorAssessor {
	return behaviorBridge{producer: producer}
}

func (b behaviorBridge) BehaviorFor(ctx context.Context, assetID shared.ID) (riskscoreuc.FactorInput, error) {
	f, err := b.producer.BehaviorFor(ctx, assetID)
	if err != nil {
		return riskscoreuc.FactorInput{}, err
	}
	return riskscoreuc.FactorInput{Score: riskassessment.Score(f.Behavior), Scoreable: f.Scoreable, Reasons: f.Reasons}, nil
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
