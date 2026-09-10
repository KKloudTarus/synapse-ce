package findinglineage

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
)

func TestSelectBackfillTargetRequiresProducerAndFindingKind(t *testing.T) {
	snapshot := assessmentsnapshot.Snapshot{Dimensions: []assessmentsnapshot.Dimension{
		{Producer: "sca", FindingKind: "misconfig", Target: assessmentsnapshot.Target{Canonical: "wrong-kind"}},
		{Producer: "sast", FindingKind: "vulnerability", Target: assessmentsnapshot.Target{Canonical: "wrong-producer"}},
		{Producer: "sca", FindingKind: "vulnerability", Target: assessmentsnapshot.Target{Canonical: "repo:expected"}},
	}}
	target := selectBackfillTarget(snapshot, "sca", "vulnerability", "assessment")
	if target.canonical != "repo:expected" || target.reasonCode != "" {
		t.Fatalf("target=%+v", target)
	}
}

func TestSelectBackfillTargetRejectsHalfMatches(t *testing.T) {
	snapshot := assessmentsnapshot.Snapshot{Dimensions: []assessmentsnapshot.Dimension{
		{Producer: "sca", FindingKind: "misconfig", Target: assessmentsnapshot.Target{Canonical: "wrong-kind"}},
		{Producer: "sast", FindingKind: "vulnerability", Target: assessmentsnapshot.Target{Canonical: "wrong-producer"}},
	}}
	target := selectBackfillTarget(snapshot, "sca", "vulnerability", "assessment")
	if target.reasonCode != BackfillReasonMissingTarget || target.canonical != "assessment:assessment" {
		t.Fatalf("target=%+v", target)
	}
}
