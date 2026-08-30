package riskscorebridge

import (
	"context"
	"testing"
)

func TestAbstainingExposureAlwaysAbstains(t *testing.T) {
	f, err := AbstainingExposure("exposure not wired").ExposureFor(context.Background(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if f.Scoreable {
		t.Fatal("abstaining exposure must not be scoreable")
	}
	if f.Score != 0 {
		t.Fatalf("an abstaining factor must contribute 0, got %d", f.Score)
	}
	if len(f.Reasons) != 1 || f.Reasons[0] != "exposure not wired" {
		t.Fatalf("reason not carried: %v", f.Reasons)
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
