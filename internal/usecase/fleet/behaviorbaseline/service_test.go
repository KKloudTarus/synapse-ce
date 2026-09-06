package behaviorbaseline

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/baselineuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeRates struct {
	counts map[detection.Class]int
	since  time.Time
	asset  shared.ID
}

func (f *fakeRates) ClassCountsByAsset(_ context.Context, assetID shared.ID, since time.Time) (map[detection.Class]int, error) {
	f.asset, f.since = assetID, since
	return f.counts, nil
}

type fakeEngine struct {
	learnedObs  baseline.Observation
	learnWin    baseline.LearnWindow
	scoreObs    baseline.Observation
	learnCalls  int
	scoreRet    baselineuc.Assessment
	rebaseKey   baseline.Key
	rebaseActor string
	rebaseCalls int
	rebaseRet   error
}

func (f *fakeEngine) Observe(_ context.Context, _ string, _ baseline.Key, obs baseline.Observation, w baseline.LearnWindow) (baselineuc.Assessment, error) {
	f.learnCalls++
	f.learnedObs = obs
	f.learnWin = w
	return baselineuc.Assessment{}, nil
}
func (f *fakeEngine) Score(_ context.Context, _ baseline.Key, obs baseline.Observation) (baselineuc.Assessment, error) {
	f.scoreObs = obs
	return f.scoreRet, nil
}
func (f *fakeEngine) Rebaseline(_ context.Context, actor string, key baseline.Key) error {
	f.rebaseCalls++
	f.rebaseActor, f.rebaseKey = actor, key
	return f.rebaseRet
}

type fakeProcs struct{ procs []ports.ProcessSnapshot }

func (f fakeProcs) ListRunningByAsset(context.Context, shared.ID) ([]ports.ProcessSnapshot, error) {
	return f.procs, nil
}

func ctxT() context.Context { return shared.WithTenant(context.Background(), "tenant-a") }

func TestObservationMapsProcessCountAndDistinctPaths(t *testing.T) {
	eng := &fakeEngine{scoreRet: baselineuc.Assessment{Behavior: 40, Scoreable: true}}
	procs := fakeProcs{procs: []ports.ProcessSnapshot{
		{Path: "/usr/sbin/nginx", Running: true}, {Path: "/usr/sbin/nginx", Running: true}, {Path: "/bin/bash", Running: true},
	}}
	svc, err := NewService(eng, procs, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Learn(ctxT(), "operator", "asset-1"); err != nil {
		t.Fatal(err)
	}
	if eng.learnCalls != 1 {
		t.Fatalf("Learn must Observe once, got %d", eng.learnCalls)
	}
	// 3 processes, 2 distinct paths.
	if eng.learnedObs.Values[baseline.FeatureProcessSpawnRate] != 3 || eng.learnedObs.Values[baseline.FeatureNewExecPaths] != 2 {
		t.Fatalf("observation mapping wrong: %+v", eng.learnedObs.Values)
	}
	// Unobserved features stay 0 (never invent a signal).
	if eng.learnedObs.Values[baseline.FeatureNetworkFanout] != 0 || eng.learnedObs.Values[baseline.FeaturePrivilegeEvents] != 0 {
		t.Fatalf("unobserved features must be 0: %+v", eng.learnedObs.Values)
	}
	// The learn window asserts process-class coverage but must be otherwise clean (no incident/emulation flags).
	if eng.learnWin.IncidentActive || eng.learnWin.Emulation || eng.learnWin.MinCoverage < 1 {
		t.Fatalf("learn window not clean: %+v", eng.learnWin)
	}

	f, err := svc.BehaviorFor(ctxT(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Scoreable || f.Behavior != 40 {
		t.Fatalf("BehaviorFor must map the Score assessment: %+v", f)
	}
}

func TestObservationFoldsDetectionClassRates(t *testing.T) {
	eng := &fakeEngine{scoreRet: baselineuc.Assessment{Behavior: 60, Scoreable: true}}
	procs := fakeProcs{procs: []ports.ProcessSnapshot{{Path: "/bin/bash", Running: true}}}
	rates := &fakeRates{counts: map[detection.Class]int{detection.ClassNetwork: 5, detection.ClassPrivilege: 2, detection.ClassFile: 3}}
	now := time.Date(2026, 2, 20, 0, 0, 0, 0, time.UTC)
	svc, err := NewService(eng, procs, rates, func() time.Time { return now }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Learn(ctxT(), "operator", "asset-1"); err != nil {
		t.Fatal(err)
	}
	// The network / privilege / file features now come from the host's recent per-class detection rate,
	// not left at 0 (the #822 fix).
	if eng.learnedObs.Values[baseline.FeatureNetworkFanout] != 5 ||
		eng.learnedObs.Values[baseline.FeaturePrivilegeEvents] != 2 ||
		eng.learnedObs.Values[baseline.FeatureFileWriteBreadth] != 3 {
		t.Fatalf("detection-fed features wrong: %+v", eng.learnedObs.Values)
	}
	// Process features are still mapped from the snapshot.
	if eng.learnedObs.Values[baseline.FeatureProcessSpawnRate] != 1 {
		t.Fatalf("process feature wrong: %+v", eng.learnedObs.Values)
	}
	// The rate is counted over [now-window, now] for exactly this asset.
	if !rates.since.Equal(now.Add(-time.Hour)) {
		t.Fatalf("detection cutoff wrong: got %v want %v", rates.since, now.Add(-time.Hour))
	}
	if rates.asset != "asset-1" {
		t.Fatalf("detection asset wrong: %v", rates.asset)
	}
}

func TestBehaviorForRequiresTenant(t *testing.T) {
	svc, _ := NewService(&fakeEngine{}, fakeProcs{}, nil, nil, 0)
	if _, err := svc.BehaviorFor(context.Background(), "asset-1"); err == nil {
		t.Fatal("a missing tenant must be rejected")
	}
}

// TestRebaselineDerivesTheAssetKeyAndDelegates: Rebaseline computes the asset's baseline key from the
// tenant + asset id and drives the engine, so an operator can reset a drifted baseline by asset id.
func TestRebaselineDerivesTheAssetKeyAndDelegates(t *testing.T) {
	eng := &fakeEngine{}
	svc, err := NewService(eng, &fakeProcs{}, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if err := svc.Rebaseline(ctx, "op@example.test", "asset-9"); err != nil {
		t.Fatalf("rebaseline: %v", err)
	}
	if eng.rebaseCalls != 1 || eng.rebaseActor != "op@example.test" {
		t.Fatalf("engine rebaseline = %d calls, actor %q", eng.rebaseCalls, eng.rebaseActor)
	}
	if eng.rebaseKey.Tenant != "tenant-a" || eng.rebaseKey.Group != "asset-9" {
		t.Fatalf("rebaseline key = %+v, want tenant-a/asset-9", eng.rebaseKey)
	}
	// A missing tenant or asset is a validation error, never a silent no-op.
	if err := svc.Rebaseline(context.Background(), "op", "asset-9"); err == nil {
		t.Fatal("a missing tenant must fail")
	}
	if err := svc.Rebaseline(ctx, "op", ""); err == nil {
		t.Fatal("a missing asset id must fail")
	}
}
