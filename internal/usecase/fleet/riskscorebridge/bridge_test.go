package riskscorebridge

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/exposureuc"
)

type fakeExposureProducer struct {
	a   exposureuc.Assessment
	err error
}

func (f fakeExposureProducer) Assess(context.Context, shared.ID) (exposureuc.Assessment, error) {
	return f.a, f.err
}

func TestNewExposureMapsAssessment(t *testing.T) {
	f, err := NewExposure(fakeExposureProducer{a: exposureuc.Assessment{Exposure: 73, Scoreable: true, Reasons: []string{"2 open exposures"}}}).ExposureFor(context.Background(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Scoreable || f.Score != 73 || len(f.Reasons) != 1 || f.Reasons[0] != "2 open exposures" {
		t.Fatalf("exposure not mapped to FactorInput: %+v", f)
	}
}

func TestNewExposurePassesAbstainThrough(t *testing.T) {
	f, err := NewExposure(fakeExposureProducer{a: exposureuc.Assessment{Scoreable: false, Reasons: []string{"no inventory"}}}).ExposureFor(context.Background(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if f.Scoreable || f.Score != 0 {
		t.Fatalf("abstain must flow through as 0/not-scoreable: %+v", f)
	}
}

func TestNewExposurePropagatesError(t *testing.T) {
	_, err := NewExposure(fakeExposureProducer{err: errors.New("store down")}).ExposureFor(context.Background(), "asset-1")
	if err == nil {
		t.Fatal("a producer error must propagate")
	}
}

func TestAbstainingBehaviorAlwaysAbstains(t *testing.T) {
	f, err := AbstainingBehavior("behavior not wired").BehaviorFor(context.Background(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if f.Scoreable || f.Score != 0 || len(f.Reasons) != 1 {
		t.Fatalf("abstaining behavior must be 0/not-scoreable with a reason: %+v", f)
	}
}

func TestAbstainingCoverageYieldsNoClasses(t *testing.T) {
	classes, err := AbstainingCoverage().ClassCoverageForAsset(context.Background(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 0 {
		t.Fatalf("abstaining coverage must yield no class coverage (all classes read as gaps), got %d", len(classes))
	}
}
