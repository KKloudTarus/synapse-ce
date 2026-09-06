package emulationrun

import (
	"context"
	"errors"
	"testing"
	"time"

	demu "github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	dexploit "github.com/KKloudTarus/synapse-ce/internal/domain/exploitation"
	offdom "github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	pcovdom "github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	exploituc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	offensivepolicyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/purplecoverage"
)

var runNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

// --- fakes ---

type fakeEngagements struct {
	eng *engdom.Engagement
	err error
}

func (f fakeEngagements) Get(_ context.Context, _, _ shared.ID) (*engdom.Engagement, error) {
	return f.eng, f.err
}

type fakeSealer struct{}

func (fakeSealer) SealOffensiveAuthorization(_ context.Context, _ shared.ID, _ []byte, createdBy string) (shared.ID, error) {
	return shared.ID("ev-" + createdBy), nil
}

type fakeAudit struct{}

func (fakeAudit) Record(_ context.Context, _ ports.AuditEntry) error { return nil }

// fakeExec always produces the observable, so admission is the only thing that decides Executed.
type fakeExec struct{}

func (fakeExec) Execute(_ context.Context, _ *dexploit.Chain, _ dexploit.Step) (exploituc.StepOutcome, error) {
	return exploituc.StepOutcome{Succeeded: true, ObservedRadius: offdom.RadiusReadOnly}, nil
}

type fakeRuns struct{ saved []demu.Run }

func (f *fakeRuns) SaveRun(_ context.Context, run demu.Run) error {
	f.saved = append(f.saved, run)
	return nil
}

// fakeCoverage stands in for the detection join. It resolves each executed technique to a gap (no
// detection) unless its id is in `covered`, mirroring what purplecoverage.Compute produces, so the test
// exercises the real "Summary is built from the join result" contract.
type fakeCoverage struct {
	calls   int
	lastRun demu.Run
	lastWin purplecoverage.Window
	covered map[string]bool
}

func (f *fakeCoverage) Compute(_ context.Context, run demu.Run, win purplecoverage.Window) (purplecoverage.Result, error) {
	f.calls++
	f.lastRun = run
	f.lastWin = win
	var cov []pcovdom.Coverage
	for _, r := range run.Coverage {
		v := pcovdom.VerdictUnknown
		if r.Executed {
			if f.covered[r.TechniqueID] {
				v = pcovdom.VerdictCovered
			} else {
				v = pcovdom.VerdictGap
			}
		}
		cov = append(cov, pcovdom.Coverage{TechniqueID: r.TechniqueID, Verdict: v})
	}
	return purplecoverage.Result{Coverage: cov}, nil
}

type fakeClock struct{}

func (fakeClock) Now() time.Time { return runNow }

type fakeIDs struct{ n int }

func (f *fakeIDs) NewID() shared.ID {
	f.n++
	return shared.ID("id-" + time.Duration(f.n).String())
}

// --- helpers ---

func completeEngagement() *engdom.Engagement {
	from := runNow.Add(-time.Hour)
	to := runNow.Add(time.Hour)
	return &engdom.Engagement{
		ID:       "eng-1",
		TenantID: "t1",
		Scope: engdom.Scope{
			InScope: []engdom.Target{{Kind: engdom.TargetDomain, Value: "app.example.test"}},
		},
		AuthorizedFrom: &from,
		AuthorizedTo:   &to,
		RoE: engdom.RoE{Offensive: engdom.OffensiveRoE{
			CustomerContact:    "ciso@client.example",
			EmergencyContact:   "+1-555-0100",
			RiskCeiling:        offdom.RiskHigh,
			ExclusionsReviewed: true,
		}},
	}
}

func productionSafeCount(t *testing.T) int {
	t.Helper()
	cat, err := demu.Catalogue()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	n := 0
	for _, tech := range cat {
		if tech.ProductionSafe {
			n++
		}
	}
	return n
}

func newRunService(t *testing.T, eng *engdom.Engagement, runs *fakeRuns, cov *fakeCoverage) *Service {
	t.Helper()
	reg, err := offdom.Load()
	if err != nil {
		t.Fatal(err)
	}
	gov, err := offensivepolicyuc.NewService(reg, fakeSealer{}, fakeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(fakeEngagements{eng: eng}, gov, fakeExec{}, runs, cov, fakeAudit{}, fakeClock{}, &fakeIDs{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func tenantCtx() context.Context {
	return shared.WithTenant(context.Background(), "t1")
}

// --- tests ---

// TestRunAuthorizesProductionSafeTechniquesUnderCompleteRoE is the vertical's core claim: with a complete
// offensive RoE, an open window and a non-empty scope, every production-safe technique is admitted through
// the #418 gate and executed, and the run is persisted and joined for coverage. Coverage stays 0 because
// no detection fired (honest gaps, not assumed-clean).
func TestRunAuthorizesProductionSafeTechniquesUnderCompleteRoE(t *testing.T) {
	runs, cov := &fakeRuns{}, &fakeCoverage{}
	svc := newRunService(t, completeEngagement(), runs, cov)

	sum, err := svc.Run(tenantCtx(), "eng-1", "app.example.test", "alice", false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantExec := productionSafeCount(t)
	if sum.Executed != wantExec {
		t.Errorf("Executed = %d, want %d (the production-safe techniques)", sum.Executed, wantExec)
	}
	if sum.Covered != 0 {
		t.Errorf("Covered = %d, want 0 (no detection fired, so every executed technique is a gap)", sum.Covered)
	}
	if sum.Techniques <= sum.Executed {
		t.Errorf("Techniques (%d) should exceed Executed (%d): the lab-only technique is refused", sum.Techniques, sum.Executed)
	}
	if len(runs.saved) != 1 {
		t.Fatalf("run persisted %d times, want 1", len(runs.saved))
	}
	if cov.calls != 1 {
		t.Fatalf("coverage computed %d times, want 1", cov.calls)
	}
	if !cov.lastWin.To.Equal(runNow) || !cov.lastWin.From.Equal(runNow.Add(-defaultCoverageWindow)) {
		t.Errorf("coverage window = [%s,%s], want [%s,%s]", cov.lastWin.From, cov.lastWin.To, runNow.Add(-defaultCoverageWindow), runNow)
	}
	if cov.lastRun.ID != runs.saved[0].ID {
		t.Errorf("coverage joined a different run than was persisted")
	}
}

// TestRunRefusesEveryTechniqueUnderIncompleteRoE proves the fail-closed default: an engagement missing a
// required offensive field authorizes nothing, so Executed is 0 even though the run still records the
// refusals and computes (empty) coverage.
func TestRunRefusesEveryTechniqueUnderIncompleteRoE(t *testing.T) {
	eng := completeEngagement()
	eng.RoE.Offensive.CustomerContact = "" // one missing field is enough to refuse
	runs, cov := &fakeRuns{}, &fakeCoverage{}
	svc := newRunService(t, eng, runs, cov)

	sum, err := svc.Run(tenantCtx(), "eng-1", "app.example.test", "alice", true)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.Executed != 0 {
		t.Errorf("Executed = %d, want 0 under an incomplete RoE", sum.Executed)
	}
	if len(runs.saved) != 1 || cov.calls != 1 {
		t.Errorf("run should still persist and compute coverage: saved=%d coverage=%d", len(runs.saved), cov.calls)
	}
}

func TestRunRequiresTenantInContext(t *testing.T) {
	runs, cov := &fakeRuns{}, &fakeCoverage{}
	svc := newRunService(t, completeEngagement(), runs, cov)
	if _, err := svc.Run(context.Background(), "eng-1", "app.example.test", "alice", false); err == nil {
		t.Fatal("expected error with no tenant in context")
	}
	if len(runs.saved) != 0 {
		t.Error("nothing should persist without a tenant")
	}
}

func TestRunRequiresEngagementAndTarget(t *testing.T) {
	svc := newRunService(t, completeEngagement(), &fakeRuns{}, &fakeCoverage{})
	if _, err := svc.Run(tenantCtx(), "", "app.example.test", "alice", false); err == nil {
		t.Error("expected error with empty engagement id")
	}
	if _, err := svc.Run(tenantCtx(), "eng-1", "", "alice", false); err == nil {
		t.Error("expected error with empty target")
	}
}

func TestRunSurfacesEngagementLoadError(t *testing.T) {
	reg, _ := offdom.Load()
	gov, _ := offensivepolicyuc.NewService(reg, fakeSealer{}, fakeAudit{})
	svc, err := NewService(fakeEngagements{err: errors.New("not found")}, gov, fakeExec{}, &fakeRuns{}, &fakeCoverage{}, fakeAudit{}, fakeClock{}, &fakeIDs{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Run(tenantCtx(), "eng-1", "app.example.test", "alice", false); err == nil {
		t.Fatal("expected the engagement load error to surface")
	}
}

func TestNewServiceValidatesDependencies(t *testing.T) {
	if _, err := NewService(nil, nil, nil, nil, nil, nil, nil, nil, 0); err == nil {
		t.Fatal("expected error when dependencies are missing")
	}
}

// TestRunRefusesCompletedEngagement is the lifecycle gate: an engagement whose assessment is over must
// not admit an offensive run even while its authorization window is still open.
func TestRunRefusesCompletedEngagement(t *testing.T) {
	eng := completeEngagement()
	eng.Status = engdom.StatusCompleted
	runs, cov := &fakeRuns{}, &fakeCoverage{}
	svc := newRunService(t, eng, runs, cov)
	if _, err := svc.Run(tenantCtx(), "eng-1", "app.example.test", "alice", false); err == nil {
		t.Fatal("expected a completed engagement to refuse the run")
	}
	if len(runs.saved) != 0 || cov.calls != 0 {
		t.Errorf("nothing should persist for a refused-by-lifecycle run: saved=%d coverage=%d", len(runs.saved), cov.calls)
	}
}

// TestRunRefusesExcludedTarget enforces the offensive excluded-assets list: a run must not be attributed
// to an asset the operator explicitly excluded, even under a complete RoE and open window.
func TestRunRefusesExcludedTarget(t *testing.T) {
	eng := completeEngagement()
	eng.RoE.Offensive.ExcludedAssets = []string{"app.example.test"}
	runs, cov := &fakeRuns{}, &fakeCoverage{}
	svc := newRunService(t, eng, runs, cov)
	if _, err := svc.Run(tenantCtx(), "eng-1", "app.example.test", "alice", false); err == nil {
		t.Fatal("expected an excluded target to refuse the run")
	}
	if len(runs.saved) != 0 {
		t.Error("nothing should persist for an excluded target")
	}
}

// TestRunSummaryReflectsDetectionJoin proves the Summary is built from the coverage join, not the
// pre-join records: when a detection covers one executed technique, the Summary reports covered > 0. This
// is the regression the QA pass caught (the endpoint previously always reported covered = 0).
func TestRunSummaryReflectsDetectionJoin(t *testing.T) {
	runs := &fakeRuns{}
	cov := &fakeCoverage{covered: map[string]bool{"emu.process_discovery": true}}
	svc := newRunService(t, completeEngagement(), runs, cov)

	sum, err := svc.Run(tenantCtx(), "eng-1", "app.example.test", "alice", false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	exec := productionSafeCount(t)
	if sum.Covered != 1 {
		t.Errorf("Covered = %d, want 1 (one technique's detection fired)", sum.Covered)
	}
	if sum.Executed != exec {
		t.Errorf("Executed = %d, want %d", sum.Executed, exec)
	}
	if sum.Gaps != exec-1 {
		t.Errorf("Gaps = %d, want %d (executed minus the one covered)", sum.Gaps, exec-1)
	}
}

// TestRunRefusesOutOfScopeTarget enforces engagement scope on the run target: a target that is not in
// scope is refused before any technique runs, matching the execution guard every other tool path uses.
func TestRunRefusesOutOfScopeTarget(t *testing.T) {
	runs, cov := &fakeRuns{}, &fakeCoverage{}
	svc := newRunService(t, completeEngagement(), runs, cov)
	if _, err := svc.Run(tenantCtx(), "eng-1", "totally-unrelated.attacker.example", "alice", false); err == nil {
		t.Fatal("expected an out-of-scope target to refuse the run")
	}
	if len(runs.saved) != 0 || cov.calls != 0 {
		t.Errorf("nothing should persist for an out-of-scope target: saved=%d coverage=%d", len(runs.saved), cov.calls)
	}
}
