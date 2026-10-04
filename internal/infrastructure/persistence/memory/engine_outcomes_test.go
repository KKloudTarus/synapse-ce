package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestScanJobStoreEngineOutcomesAreIsolatedAcrossReads(t *testing.T) {
	store := NewScanJobStore()
	started := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	job := ports.ScanJob{
		ID: "engine-outcomes-job", EngagementID: "engine-outcomes-engagement", Target: "repo", Kind: ports.TargetGit,
		Status: ports.ScanRunning, StartedAt: started,
		EngineOutcomes: []scanrun.EngineOutcome{{
			Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true,
			Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFindings: 0},
		}},
	}
	if err := store.CreateRunning(context.Background(), job); err != nil {
		t.Fatalf("create running job: %v", err)
	}

	// The store must own a deep copy, including the nested count map.
	job.EngineOutcomes[0].Counts[scanrun.MeasureFindings] = 99
	progress := job
	progress.Stage = "collecting"
	progress.EngineOutcomes = []scanrun.EngineOutcome{{
		Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true,
		Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFindings: 0},
	}}
	if err := store.Save(context.Background(), progress); err != nil {
		t.Fatalf("save structured progress: %v", err)
	}
	got, err := store.GetJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	assertCompleteEngineJob(t, got)
	got.EngineOutcomes[0].Counts[scanrun.MeasureFindings] = 41

	for name, read := range map[string]func() (ports.ScanJob, error){
		"get": func() (ports.ScanJob, error) { return store.GetJob(context.Background(), job.ID) },
		"latest": func() (ports.ScanJob, error) {
			return store.LatestForEngagement(context.Background(), shared.ID(job.EngagementID))
		},
		"batch latest": func() (ports.ScanJob, error) {
			jobs, err := store.LatestForEngagements(context.Background(), []shared.ID{shared.ID(job.EngagementID)})
			return jobs[shared.ID(job.EngagementID)], err
		},
		"stale": func() (ports.ScanJob, error) {
			jobs, err := store.ListStaleRunning(context.Background(), started.Add(time.Hour), 1)
			if err != nil || len(jobs) != 1 {
				if err == nil {
					err = shared.ErrNotFound
				}
				return ports.ScanJob{}, err
			}
			return jobs[0], nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			loaded, err := read()
			if err != nil {
				t.Fatalf("read job: %v", err)
			}
			assertCompleteEngineJob(t, loaded)
		})
	}

	if err := store.Save(context.Background(), ports.ScanJob{
		ID: "historic-engine-outcomes-job", EngagementID: "historic-engine-outcomes", Target: "repo", Kind: ports.TargetGit,
		Status: ports.ScanSucceeded, StartedAt: started,
	}); err != nil {
		t.Fatalf("save historical job: %v", err)
	}
	historical, err := store.GetJob(context.Background(), "historic-engine-outcomes-job")
	if err != nil {
		t.Fatalf("get historical job: %v", err)
	}
	if historical.EngineCoverage.Status != scanrun.CoverageUnknown || historical.EngineCoverage.Required != 0 {
		t.Fatalf("historical job coverage = %+v, want unknown without invented outcomes", historical.EngineCoverage)
	}
}

func TestScanRunStoreSealsEngineOutcomesWithoutChangingLegacyProofs(t *testing.T) {
	store := NewScanRunStore()
	ctx := context.Background()
	tenantID := shared.ID("engine-outcomes-tenant")
	engagementID := shared.ID("engine-outcomes-engagement")
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	target, err := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	if err != nil {
		t.Fatalf("canonicalize target: %v", err)
	}

	seal := func(runID string, version int, outcomes []scanrun.EngineOutcome) scanrun.Lane {
		t.Helper()
		run := scanrun.ScanRun{TenantID: tenantID, EngagementID: engagementID, ID: runID, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding, ManifestSchemaVersion: version, CreatedAt: now, UpdatedAt: now}
		if err := store.SaveScanRun(ctx, run); err != nil {
			t.Fatalf("save building run: %v", err)
		}
		lane := scanrun.Lane{TenantID: tenantID, EngagementID: engagementID, ScanRunID: runID, LaneKey: "sast", Producer: "synapse-sast", TerminalStatus: scanrun.StatusSucceeded, Target: target, AuthoritativeFindingKinds: []string{"sast_vuln"}, StartedAt: now, ManifestSchemaVersion: version, Stages: []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: now}}, EngineOutcomes: outcomes}
		lane.ManifestHash, err = scanrun.ComputeManifestHash(lane)
		if err != nil {
			t.Fatalf("compute lane hash: %v", err)
		}
		runHash, err := scanrun.ComputeRunManifestHash([]scanrun.Lane{lane})
		if err != nil {
			t.Fatalf("compute run hash: %v", err)
		}
		if err := store.SealScanRun(ctx, ports.SealScanRunCommand{TenantID: tenantID, RunID: runID, TerminalStatus: scanrun.StatusSucceeded, Lanes: []scanrun.Lane{lane}, ManifestSchemaVersion: version, ManifestHash: runHash, SealedAt: now}); err != nil {
			t.Fatalf("seal run: %v", err)
		}
		return lane
	}

	lane := seal("engine-outcomes-run", 2, []scanrun.EngineOutcome{{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true, Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFindings: 0}}})
	lane.EngineOutcomes[0].Counts[scanrun.MeasureFindings] = 12
	loaded, err := store.GetScanRun(ctx, tenantID, "engine-outcomes-run")
	if err != nil {
		t.Fatalf("load sealed run: %v", err)
	}
	if len(loaded.Lanes) != 1 || loaded.Lanes[0].EngineOutcomes[0].Counts[scanrun.MeasureFindings] != 0 || !loaded.IsCompleteCoverage() {
		t.Fatalf("sealed engine outcomes were not restored: %+v", loaded)
	}
	if hash, err := scanrun.ComputeRunManifestHash(loaded.Lanes); err != nil || hash != loaded.ManifestHash {
		t.Fatalf("sealed hash verification = %q, %v; want %q", hash, err, loaded.ManifestHash)
	}
	loaded.Lanes[0].EngineOutcomes[0].Counts[scanrun.MeasureFindings] = 13
	again, err := store.GetScanRun(ctx, tenantID, "engine-outcomes-run")
	if err != nil || again.Lanes[0].EngineOutcomes[0].Counts[scanrun.MeasureFindings] != 0 {
		t.Fatalf("reader mutation altered sealed evidence: %+v err=%v", again, err)
	}

	seal("legacy-engine-outcomes-run", 1, nil)
	legacy, err := store.GetScanRun(ctx, tenantID, "legacy-engine-outcomes-run")
	if err != nil || !legacy.IsCompleteCoverage() || len(legacy.Lanes[0].EngineOutcomes) != 0 {
		t.Fatalf("legacy schema proof changed: %+v err=%v", legacy, err)
	}
}

func assertCompleteEngineJob(t *testing.T, job ports.ScanJob) {
	t.Helper()
	if len(job.EngineOutcomes) != 1 || job.EngineOutcomes[0].Counts[scanrun.MeasureFindings] != 0 {
		t.Fatalf("engine outcomes changed during persistence: %+v", job.EngineOutcomes)
	}
	if !job.EngineCoverage.Complete() || job.EngineCoverage.Required != 1 || job.EngineCoverage.Completed != 1 {
		t.Fatalf("engine coverage = %+v, want one complete required engine", job.EngineCoverage)
	}
}
