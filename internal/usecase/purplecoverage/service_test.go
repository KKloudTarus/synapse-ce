package purplecoverage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	pcdom "github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// fakeDetections is a detection ledger that returns canned records; the join filters them by asset+window.
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

type fakeAudit struct {
	entries []ports.AuditEntry
	fail    bool
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	if a.fail {
		return errors.New("audit down")
	}
	a.entries = append(a.entries, e)
	return nil
}

func tctx() context.Context { return shared.WithTenant(context.Background(), "t1") }

func newSvc(t *testing.T, det *fakeDetections, audit *fakeAudit) (*Service, ports.PurpleCoverageStore) {
	t.Helper()
	store := memory.NewPurpleStore()
	svc, err := NewService(store, det, audit, fixedClock{t: time.Unix(2000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return svc, store
}

func firedDetection(rule string, asset shared.ID, at time.Time) detection.Record {
	return detection.Record{
		AssetID:   asset,
		Detection: detection.Detection{RuleID: rule, Observed: at},
	}
}

// TestComputeResolvesCoveredGapUnknownFromTheTwoHalves is the core join: covered when the expected
// detection fired in the window on the asset, gap when it did not, unknown when the technique did not run.
func TestComputeResolvesCoveredGapUnknownFromTheTwoHalves(t *testing.T) {
	window := time.Unix(1500, 0)
	det := &fakeDetections{records: []detection.Record{
		firedDetection("det.covered", "asset-1", window),     // expected by emu.covered → covered
		firedDetection("det.surprise", "asset-1", window),    // matches no technique → bonus
		firedDetection("det.covered", "asset-OTHER", window), // right rule, WRONG asset → must not count
	}}
	audit := &fakeAudit{}
	svc, store := newSvc(t, det, audit)

	run := emulation.Run{
		ID: "run-1", TenantID: "t1", EngagementID: "eng-1", Target: "asset-1", Actor: "op@x",
		Coverage: []emulation.CoverageRecord{
			{TechniqueID: "emu.covered", TaxonomyRef: "T1", Executed: true, Expected: "det.covered"},
			{TechniqueID: "emu.gap", TaxonomyRef: "T2", Executed: true, Expected: "det.gap"},
			{TechniqueID: "emu.unknown", TaxonomyRef: "T3", Executed: false, Expected: "det.unknown"},
		},
	}

	res, err := svc.Compute(tctx(), run, Window{From: time.Unix(1000, 0), To: time.Unix(2000, 0)})
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	got := map[string]pcdom.Verdict{}
	for _, c := range res.Coverage {
		got[c.TechniqueID] = c.Verdict
	}
	if got["emu.covered"] != pcdom.VerdictCovered {
		t.Errorf("emu.covered = %s, want covered", got["emu.covered"])
	}
	if got["emu.gap"] != pcdom.VerdictGap {
		t.Errorf("emu.gap = %s, want gap", got["emu.gap"])
	}
	if got["emu.unknown"] != pcdom.VerdictUnknown {
		t.Errorf("emu.unknown = %s, want unknown (never gap)", got["emu.unknown"])
	}
	if len(res.Bonus) != 1 || res.Bonus[0] != "det.surprise" {
		t.Errorf("bonus = %v, want [det.surprise]", res.Bonus)
	}
	if len(res.Gaps) != 1 || res.Gaps[0].TechniqueID != "emu.gap" {
		t.Errorf("gaps = %+v, want one for emu.gap", res.Gaps)
	}
	// Persisted, so a trend/regression query later sees it.
	stored, err := store.ListByRun(tctx(), "run-1")
	if err != nil || len(stored) != 3 {
		t.Fatalf("stored coverage = %d (%v), want 3", len(stored), err)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "purple.coverage_computed" {
		t.Fatalf("computation must be audited exactly once, got %+v", audit.entries)
	}
}

// TestComputeWindowExcludesDetectionsOutsideRange proves a detection observed outside the window does not
// count as coverage — otherwise a later run's detection could paper over an earlier gap.
func TestComputeWindowExcludesDetectionsOutsideRange(t *testing.T) {
	det := &fakeDetections{records: []detection.Record{
		firedDetection("det.a", "asset-1", time.Unix(9999, 0)), // outside [1000,2000]
	}}
	svc, _ := newSvc(t, det, &fakeAudit{})
	run := emulation.Run{ID: "run-1", TenantID: "t1", EngagementID: "eng-1", Target: "asset-1",
		Coverage: []emulation.CoverageRecord{{TechniqueID: "emu.a", TaxonomyRef: "T1", Executed: true, Expected: "det.a"}}}
	res, err := svc.Compute(tctx(), run, Window{From: time.Unix(1000, 0), To: time.Unix(2000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage[0].Verdict != pcdom.VerdictGap {
		t.Fatalf("a detection outside the window must not close the gap, got %s", res.Coverage[0].Verdict)
	}
}

func fullWindow() Window { return Window{From: time.Unix(1000, 0), To: time.Unix(2000, 0)} }

// TestComputeRejectsForeignTenantRun fails closed if the run claims a tenant other than the authenticated
// one — a run must not be scored into another tenant's ledger.
func TestComputeRejectsForeignTenantRun(t *testing.T) {
	svc, _ := newSvc(t, &fakeDetections{}, &fakeAudit{})
	run := emulation.Run{ID: "run-1", TenantID: "t2", EngagementID: "eng-1", Target: "asset-1",
		Coverage: []emulation.CoverageRecord{{TechniqueID: "emu.a", TaxonomyRef: "T1", Executed: true, Expected: "det.a"}}}
	_, err := svc.Compute(tctx(), run, fullWindow())
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant run must be forbidden, got %v", err)
	}
}

// TestComputeRequiresBoundedWindowAndTarget proves the false-covered guards fail closed: an unbounded
// window or a run with no target asset is refused, so an all-time / cross-asset join can never happen.
func TestComputeRequiresBoundedWindowAndTarget(t *testing.T) {
	svc, _ := newSvc(t, &fakeDetections{}, &fakeAudit{})
	base := emulation.Run{ID: "run-1", TenantID: "t1", EngagementID: "eng-1", Target: "asset-1",
		Coverage: []emulation.CoverageRecord{{TechniqueID: "emu.a", TaxonomyRef: "T1", Executed: true, Expected: "det.a"}}}
	if _, err := svc.Compute(tctx(), base, Window{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an unbounded window must be refused, got %v", err)
	}
	if _, err := svc.Compute(tctx(), base, Window{From: time.Unix(2000, 0), To: time.Unix(1000, 0)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a reversed window must be refused, got %v", err)
	}
	noTarget := base
	noTarget.Target = ""
	if _, err := svc.Compute(tctx(), noTarget, fullWindow()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a run with no target asset must be refused, got %v", err)
	}
}

// TestComputeFailsWhenUnauditedAndStoresNothing proves an un-attributable coverage computation is not
// presented as measured AND leaves no row behind: a failed audit fails the whole computation, and because
// the audit is written before the save, nothing is persisted.
func TestComputeFailsWhenUnauditedAndStoresNothing(t *testing.T) {
	svc, store := newSvc(t, &fakeDetections{}, &fakeAudit{fail: true})
	run := emulation.Run{ID: "run-1", TenantID: "t1", EngagementID: "eng-1", Target: "asset-1",
		Coverage: []emulation.CoverageRecord{{TechniqueID: "emu.a", TaxonomyRef: "T1", Executed: true, Expected: "det.a"}}}
	_, err := svc.Compute(tctx(), run, fullWindow())
	if err == nil || !strings.Contains(err.Error(), "audited") {
		t.Fatalf("a failed audit must fail the computation, got %v", err)
	}
	if stored, _ := store.ListByRun(tctx(), "run-1"); len(stored) != 0 {
		t.Fatalf("no coverage row may exist when the audit failed, got %d", len(stored))
	}
}

// TestWorkItemsBoundRunToEngagement proves a run id from another engagement in the same tenant resolves
// to no work items — the within-tenant cross-engagement read is closed.
func TestWorkItemsBoundRunToEngagement(t *testing.T) {
	det := &fakeDetections{}
	svc, _ := newSvc(t, det, &fakeAudit{})
	run := emulation.Run{ID: "run-1", TenantID: "t1", EngagementID: "eng-1", Target: "asset-1",
		Coverage: []emulation.CoverageRecord{{TechniqueID: "emu.gap", TaxonomyRef: "T1", Executed: true, Expected: "det.gap"}}}
	if _, err := svc.Compute(tctx(), run, fullWindow()); err != nil {
		t.Fatal(err)
	}
	// Correct engagement → one gap work item.
	if items, err := svc.WorkItems(tctx(), "eng-1", "run-1"); err != nil || len(items) != 1 {
		t.Fatalf("same-engagement work items = %d (%v), want 1", len(items), err)
	}
	// Different engagement, same tenant → the run's items must NOT leak.
	if items, err := svc.WorkItems(tctx(), "eng-OTHER", "run-1"); err != nil || len(items) != 0 {
		t.Fatalf("cross-engagement work items must be empty, got %d (%v)", len(items), err)
	}
}

// TestRegressionsAcrossRuns proves a covered→gap transition between two runs is surfaced as a regression.
func TestRegressionsAcrossRuns(t *testing.T) {
	det := &fakeDetections{}
	audit := &fakeAudit{}
	svc, _ := newSvc(t, det, audit)

	base := emulation.Run{ID: "run-1", TenantID: "t1", EngagementID: "eng-1", Target: "asset-1",
		Coverage: []emulation.CoverageRecord{{TechniqueID: "emu.a", TaxonomyRef: "T1", Executed: true, Expected: "det.a"}}}
	// Run 1: det.a fired → covered.
	det.records = []detection.Record{firedDetection("det.a", "asset-1", time.Unix(1500, 0))}
	if _, err := svc.Compute(tctx(), base, Window{From: time.Unix(1000, 0), To: time.Unix(2000, 0)}); err != nil {
		t.Fatal(err)
	}
	// Run 2: same technique, det.a did NOT fire → gap (a detection regression).
	run2 := base
	run2.ID = "run-2"
	det.records = nil
	if _, err := svc.Compute(tctx(), run2, Window{From: time.Unix(1000, 0), To: time.Unix(2000, 0)}); err != nil {
		t.Fatal(err)
	}
	regs, err := svc.Regressions(tctx(), "run-1", "run-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 || regs[0].TechniqueID != "emu.a" || regs[0].To != pcdom.VerdictGap {
		t.Fatalf("expected one covered->gap regression, got %+v", regs)
	}
}
