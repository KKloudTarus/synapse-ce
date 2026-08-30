package behaviorbaseline

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/baselineuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeEngine struct {
	learnedObs baseline.Observation
	learnWin   baseline.LearnWindow
	scoreObs   baseline.Observation
	learnCalls int
	scoreRet   baselineuc.Assessment
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
	svc, err := NewService(eng, procs)
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

func TestBehaviorForRequiresTenant(t *testing.T) {
	svc, _ := NewService(&fakeEngine{}, fakeProcs{})
	if _, err := svc.BehaviorFor(context.Background(), "asset-1"); err == nil {
		t.Fatal("a missing tenant must be rejected")
	}
}
