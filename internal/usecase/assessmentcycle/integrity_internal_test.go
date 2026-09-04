package assessmentcycle

import (
	"testing"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestVerifyIntegritySubjectCorruptionFixtures(t *testing.T) {
	clean := integritySubjectFixture(t)
	if findings := verifyIntegritySubject("run", clean, time.Now().UTC()); len(findings) != 0 {
		t.Fatalf("clean fixture findings = %+v", findings)
	}
	tests := []struct {
		name   string
		mutate func(*ports.AssessmentCycleIntegritySubject)
		want   string
	}{
		{name: "missing coverage", mutate: func(subject *ports.AssessmentCycleIntegritySubject) { subject.Cycles = nil }, want: IntegrityCoverageMissing},
		{name: "multiple coverage", mutate: func(subject *ports.AssessmentCycleIntegritySubject) {
			subject.Cycles = append(subject.Cycles, subject.Cycles[0])
		}, want: IntegrityCoverageMultiple},
		{name: "root cardinality", mutate: func(subject *ports.AssessmentCycleIntegritySubject) {
			subject.Cycles[0].Members = subject.Cycles[0].Members[1:]
		}, want: IntegrityRootCardinality},
		{name: "boundary mismatch", mutate: func(subject *ports.AssessmentCycleIntegritySubject) {
			subject.Cycles[0].Members[0].BusinessAssetID = "asset-1"
		}, want: IntegrityBoundaryMismatch},
		{name: "selected head not leaf", mutate: func(subject *ports.AssessmentCycleIntegritySubject) {
			subject.Cycles[0].Cycle.SelectedHeadAssessmentID = "root"
		}, want: IntegritySelectedHeadNotLeaf},
		{name: "selected head archived", mutate: func(subject *ports.AssessmentCycleIntegritySubject) {
			archived := time.Now().UTC()
			subject.Cycles[0].Members[1].Member.ArchivedAt = &archived
		}, want: IntegritySelectedHeadArchived},
		{name: "predecessor missing", mutate: func(subject *ports.AssessmentCycleIntegritySubject) {
			subject.Cycles[0].Members[1].Member.PredecessorAssessmentID = "missing"
		}, want: IntegrityPredecessorMissing},
		{name: "graph cycle", mutate: func(subject *ports.AssessmentCycleIntegritySubject) {
			subject.Cycles[0].Members[0].Member.AssessmentType = cycledom.AssessmentTypeRetest
			subject.Cycles[0].Members[0].Member.RetestNumber = 2
			subject.Cycles[0].Members[0].Member.PredecessorAssessmentID = "retest"
		}, want: IntegrityGraphCycle},
		{name: "next retest not monotonic", mutate: func(subject *ports.AssessmentCycleIntegritySubject) { subject.Cycles[0].Cycle.NextRetestNumber = 1 }, want: IntegrityNextRetestNotMonotonic},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subject := integritySubjectFixture(t)
			test.mutate(&subject)
			findings := verifyIntegritySubject("run", subject, time.Now().UTC())
			found := false
			for _, finding := range findings {
				if finding.ReasonCode == test.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("findings = %+v, want %s", findings, test.want)
			}
		})
	}
}

func integritySubjectFixture(t *testing.T) ports.AssessmentCycleIntegritySubject {
	t.Helper()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	cycle, err := cycledom.NewAssessmentCycle("cycle", "tenant", "Cycle", cycledom.BoundaryStandalone, "", "", "root", "owner", now)
	if err != nil {
		t.Fatal(err)
	}
	cycle.SelectedHeadAssessmentID, cycle.NextRetestNumber = "retest", 2
	root, err := cycledom.NewInitialMember("tenant", "cycle", "root", "owner", now)
	if err != nil {
		t.Fatal(err)
	}
	retest, err := cycledom.NewRetestMember("tenant", "cycle", "retest", "root", 1, "owner", now)
	if err != nil {
		t.Fatal(err)
	}
	return ports.AssessmentCycleIntegritySubject{
		TenantID: "tenant", AssessmentID: "root",
		Cycles: []ports.AssessmentCycleIntegrityCycle{{Cycle: *cycle, CycleExists: true, SubjectMembershipCount: 1, Members: []ports.AssessmentCycleIntegrityMember{
			{Member: *root, AssessmentExists: true, AssessmentStatus: engdom.StatusActive},
			{Member: *retest, AssessmentExists: true, AssessmentStatus: engdom.StatusActive},
		}}},
	}
}
