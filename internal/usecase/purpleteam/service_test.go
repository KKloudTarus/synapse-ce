package purpleteam

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	dpolicy "github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	pcdom "github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	exploituc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	offensivepolicyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	purplecoverageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/purplecoverage"
)

type fakeAudit struct{}

func (fakeAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDs struct{ n int }

func (g *seqIDs) NewID() shared.ID { g.n++; return shared.ID(fmt.Sprintf("id-%d", g.n)) }

// fakeDetections is a detection ledger returning canned records; the coverage join filters by asset+window.
type fakeDetections struct{ records []detection.Record }

func (f *fakeDetections) AppendDetection(context.Context, detection.Record) error { return nil }
func (f *fakeDetections) HasDetection(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}
func (f *fakeDetections) ListDetections(context.Context, shared.ID) ([]detection.Record, error) {
	return f.records, nil
}
func (f *fakeDetections) LastBatchSequence(context.Context, shared.ID) (uint64, error) { return 0, nil }
func (f *fakeDetections) ListExpiredDetections(context.Context, shared.ID, time.Time) ([]shared.ID, error) {
	return nil, nil
}
func (f *fakeDetections) DeleteDetection(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}

func harness(t *testing.T, now time.Time) (*Service, *memory.EngagementRepository) {
	svc, engs, _ := harnessWith(t, now, &fakeDetections{})
	return svc, engs
}

func harnessWith(t *testing.T, now time.Time, dets *fakeDetections) (*Service, *memory.EngagementRepository, *fakeDetections) {
	t.Helper()
	register, err := dpolicy.Load()
	if err != nil {
		t.Fatalf("load offensive register: %v", err)
	}
	sealer := offensivepolicyuc.NewEvidenceChainSealer(func(context.Context, shared.ID, string, []byte, string) (shared.ID, error) {
		return "ev", nil
	})
	gov, err := offensivepolicyuc.NewService(register, sealer, fakeAudit{})
	if err != nil {
		t.Fatalf("offensive policy service: %v", err)
	}
	engs := memory.NewEngagementRepository()
	runs := memory.NewEmulationRunStore()
	purple, err := purplecoverageuc.NewService(memory.NewPurpleStore(), dets, fakeAudit{}, fixedClock{now})
	if err != nil {
		t.Fatalf("purple coverage service: %v", err)
	}
	svc, err := NewService(engs, gov, exploituc.SimulationExecutor{}, runs, purple, fakeAudit{}, fixedClock{now}, &seqIDs{})
	if err != nil {
		t.Fatalf("purpleteam service: %v", err)
	}
	return svc, engs, dets
}

func makeEngagement(t *testing.T, engs *memory.EngagementRepository, now time.Time, complete bool) shared.ID {
	t.Helper()
	e, err := engagement.New("eng-1", "t1", "Eng", "Client", now)
	if err != nil {
		t.Fatal(err)
	}
	e.Scope.InScope = []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.test"}}
	if complete {
		from, to := now.Add(-time.Hour), now.Add(time.Hour)
		if err := e.SetAuthorizationWindow(&from, &to, "UTC", now); err != nil {
			t.Fatal(err)
		}
		if err := e.SetOffensiveRoE("Ops", "+1", "high", true, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := engs.Create(shared.WithTenant(context.Background(), "t1"), e); err != nil {
		t.Fatal(err)
	}
	return e.ID
}

func TestRunEmulationProducesCoverageUnderCompleteRoE(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	svc, engs := harness(t, now)
	engID := makeEngagement(t, engs, now, true)

	res, err := svc.RunEmulation(context.Background(), "t1", engID, "asset-1", "operator")
	if err != nil {
		t.Fatalf("RunEmulation: %v", err)
	}
	if len(res.Run.Coverage) == 0 {
		t.Fatal("run produced no technique coverage records")
	}
	if res.Run.Target != "asset-1" {
		t.Errorf("run target = %q, want asset-1", res.Run.Target)
	}
	// Under a complete, high-ceiling RoE at least one production-safe technique is admitted and executed.
	executed := 0
	for _, c := range res.Run.Coverage {
		if c.Executed {
			executed++
		}
	}
	if executed == 0 {
		t.Fatal("no technique executed under a complete RoE; the governance gate refused everything")
	}
	// Coverage was computed over the run (a slice, possibly all gaps since no detections fired).
	if res.Coverage.Coverage == nil {
		t.Fatal("purple coverage was not computed")
	}
}

func TestRunEmulationRefusesEveryTechniqueWithoutRoE(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	svc, engs := harness(t, now)
	engID := makeEngagement(t, engs, now, false) // no RoE, no window

	res, err := svc.RunEmulation(context.Background(), "t1", engID, "asset-1", "operator")
	if err != nil {
		t.Fatalf("RunEmulation: %v", err)
	}
	for _, c := range res.Run.Coverage {
		if c.Executed {
			t.Fatalf("technique %s executed without rules of engagement", c.TechniqueID)
		}
	}
}

func TestRunEmulationRequiresTarget(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	svc, engs := harness(t, now)
	engID := makeEngagement(t, engs, now, true)
	if _, err := svc.RunEmulation(context.Background(), "t1", engID, "", "operator"); err == nil {
		t.Fatal("RunEmulation without a target was accepted")
	}
}

func TestRunEmulationDoesNotCountDetectionsFiredBeforeTheRun(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	// A detection for emu.process_discovery's expected rule fired on asset-1 three minutes BEFORE the run.
	// The no-host executor produces no telemetry, so this stale detection must NOT mark the technique
	// covered: the coverage window starts at the run start, and a pre-run detection is a different event.
	dets := &fakeDetections{records: []detection.Record{{
		AssetID:      "asset-1",
		EngagementID: "eng-1",
		Detection:    detection.Detection{RuleID: "det.process_enumeration", Observed: now.Add(-3 * time.Minute)},
	}}}
	svc, engs, _ := harnessWith(t, now, dets)
	engID := makeEngagement(t, engs, now, true)

	res, err := svc.RunEmulation(context.Background(), "t1", engID, "asset-1", "operator")
	if err != nil {
		t.Fatalf("RunEmulation: %v", err)
	}
	for _, c := range res.Coverage.Coverage {
		if c.Verdict == pcdom.VerdictCovered {
			t.Fatalf("technique %s was marked covered by a detection that fired before the run", c.TechniqueID)
		}
	}
}
