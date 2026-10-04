package postgres

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresScanRunStoreSealsEngineOutcomesAndPreservesLegacyProof(t *testing.T) {
	ctx, pool := setupScanRunTestDB(t)
	store := NewScanRunStore(pool)
	tenantID := shared.ID("engine-outcomes-tenant-" + randHex(t))
	engagementID := shared.ID("engine-outcomes-engagement-" + randHex(t))
	runID := "engine-outcomes-run-" + randHex(t)
	ensureScanRunTenantAndEngagement(t, ctx, pool, tenantID, engagementID)
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	target, err := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	if err != nil {
		t.Fatalf("canonicalize target: %v", err)
	}
	run := scanrun.ScanRun{TenantID: tenantID, EngagementID: engagementID, ID: runID, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding, ManifestSchemaVersion: 2, CreatedAt: now, UpdatedAt: now}
	if err := store.SaveScanRun(ctx, run); err != nil {
		t.Fatalf("save building run: %v", err)
	}
	lane := scanrun.Lane{
		TenantID: tenantID, EngagementID: engagementID, ScanRunID: runID, LaneKey: "sast", Producer: "synapse-sast",
		TerminalStatus: scanrun.StatusSucceeded, Target: target, AuthoritativeFindingKinds: []string{"sast_vuln"},
		StartedAt: now, ManifestSchemaVersion: 2,
		Stages: []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: now}},
		EngineOutcomes: []scanrun.EngineOutcome{{
			Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true,
			Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFindings: 0},
		}},
	}
	laneHash, err := scanrun.ComputeManifestHash(lane)
	if err != nil {
		t.Fatalf("compute lane hash: %v", err)
	}
	lane.ManifestHash = laneHash
	runHash, err := scanrun.ComputeRunManifestHash([]scanrun.Lane{lane})
	if err != nil {
		t.Fatalf("compute run hash: %v", err)
	}
	if err := store.SealScanRun(ctx, ports.SealScanRunCommand{TenantID: tenantID, RunID: runID, TerminalStatus: scanrun.StatusSucceeded, Lanes: []scanrun.Lane{lane}, ManifestSchemaVersion: 2, ManifestHash: runHash, SealedAt: now}); err != nil {
		t.Fatalf("seal run: %v", err)
	}

	// Mutating either caller-owned or returned data cannot alter sealed facts.
	lane.EngineOutcomes[0].Counts[scanrun.MeasureFindings] = 10
	loaded, err := store.GetScanRun(ctx, tenantID, runID)
	if err != nil {
		t.Fatalf("get sealed run: %v", err)
	}
	if len(loaded.Lanes) != 1 || loaded.Lanes[0].EngineOutcomes[0].Counts[scanrun.MeasureFindings] != 0 || !loaded.IsCompleteCoverage() {
		t.Fatalf("sealed outcome facts were not faithfully restored: %+v", loaded)
	}
	if recomputed, err := scanrun.ComputeRunManifestHash(loaded.Lanes); err != nil || recomputed != loaded.ManifestHash {
		t.Fatalf("loaded sealed evidence no longer verifies: hash=%q err=%v want=%q", recomputed, err, loaded.ManifestHash)
	}
	if _, err := pool.Exec(ctx, `UPDATE scan_run_lanes SET engine_outcomes = '[]'::jsonb WHERE tenant_id = $1 AND scan_run_id = $2`, tenantID, runID); err == nil {
		t.Fatal("database allowed recorded engine outcomes to be removed from a sealed lane")
	}
	loaded.Lanes[0].EngineOutcomes[0].Counts[scanrun.MeasureFindings] = 13
	again, err := store.GetScanRun(ctx, tenantID, runID)
	if err != nil || again.Lanes[0].EngineOutcomes[0].Counts[scanrun.MeasureFindings] != 0 {
		t.Fatalf("returned mutation altered persisted evidence: %+v err=%v", again, err)
	}

	legacyRunID := "legacy-engine-outcomes-" + randHex(t)
	legacy := scanrun.ScanRun{TenantID: tenantID, EngagementID: engagementID, ID: legacyRunID, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding, ManifestSchemaVersion: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.SaveScanRun(ctx, legacy); err != nil {
		t.Fatalf("save legacy-schema run: %v", err)
	}
	legacyLane := scanrun.Lane{TenantID: tenantID, EngagementID: engagementID, ScanRunID: legacyRunID, LaneKey: "legacy-sast", Producer: "synapse-sast", TerminalStatus: scanrun.StatusSucceeded, Target: target, AuthoritativeFindingKinds: []string{"sast_vuln"}, StartedAt: now, ManifestSchemaVersion: 1, Stages: []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: now}}}
	legacyLane.ManifestHash, err = scanrun.ComputeManifestHash(legacyLane)
	if err != nil {
		t.Fatalf("compute legacy lane hash: %v", err)
	}
	legacyHash, err := scanrun.ComputeRunManifestHash([]scanrun.Lane{legacyLane})
	if err != nil {
		t.Fatalf("compute legacy run hash: %v", err)
	}
	if err := store.SealScanRun(ctx, ports.SealScanRunCommand{TenantID: tenantID, RunID: legacyRunID, TerminalStatus: scanrun.StatusSucceeded, Lanes: []scanrun.Lane{legacyLane}, ManifestSchemaVersion: 1, ManifestHash: legacyHash, SealedAt: now}); err != nil {
		t.Fatalf("seal legacy schema run: %v", err)
	}
	legacyLoaded, err := store.GetScanRun(ctx, tenantID, legacyRunID)
	if err != nil || !legacyLoaded.IsCompleteCoverage() || len(legacyLoaded.Lanes[0].EngineOutcomes) != 0 {
		t.Fatalf("legacy proof compatibility changed: %+v err=%v", legacyLoaded, err)
	}
}

func TestPostgresScanJobStoreRoundTripsEngineOutcomesAcrossReadPaths(t *testing.T) {
	ctx, pool := setupScanRunTestDB(t)
	store := NewScanJobStore(pool)
	started := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	job := ports.ScanJob{ID: "engine-outcomes-job-" + randHex(t), EngagementID: "engine-outcomes-engagement-" + randHex(t), Target: "repo", Kind: ports.TargetGit, Status: ports.ScanRunning, StartedAt: started,
		EngineOutcomes: []scanrun.EngineOutcome{{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true, Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFindings: 0}}}}
	if err := store.CreateRunning(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	job.EngineOutcomes[0].Counts[scanrun.MeasureFindings] = 99
	progress := job
	progress.Stage = "collecting"
	progress.EngineOutcomes = []scanrun.EngineOutcome{{Engine: "sast", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true, Counts: map[scanrun.EngineMeasure]int64{scanrun.MeasureFindings: 0}}}
	if err := store.Save(ctx, progress); err != nil {
		t.Fatalf("save structured progress: %v", err)
	}

	assertPostgresEngineJob := func(t *testing.T, got ports.ScanJob, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("read job: %v", err)
		}
		if len(got.EngineOutcomes) != 1 || got.EngineOutcomes[0].Counts[scanrun.MeasureFindings] != 0 || !got.EngineCoverage.Complete() {
			t.Fatalf("engine outcomes did not round-trip: %+v", got)
		}
	}
	got, err := store.GetJob(ctx, job.ID)
	assertPostgresEngineJob(t, got, err)
	got.EngineOutcomes[0].Counts[scanrun.MeasureFindings] = 7
	got, err = store.LatestForEngagement(ctx, shared.ID(job.EngagementID))
	assertPostgresEngineJob(t, got, err)
	batch, err := store.LatestForEngagements(ctx, []shared.ID{shared.ID(job.EngagementID)})
	if err != nil {
		t.Fatalf("batch latest: %v", err)
	}
	assertPostgresEngineJob(t, batch[shared.ID(job.EngagementID)], nil)
	stale, err := store.ListStaleRunning(ctx, started.Add(time.Hour), 1)
	if err != nil || len(stale) != 1 {
		t.Fatalf("stale jobs = %+v, %v", stale, err)
	}
	assertPostgresEngineJob(t, stale[0], nil)

	historical := ports.ScanJob{ID: "historic-engine-outcomes-job-" + randHex(t), EngagementID: "historic-engine-outcomes-engagement-" + randHex(t), Target: "repo", Kind: ports.TargetGit, Status: ports.ScanSucceeded, StartedAt: started}
	if err := store.Save(ctx, historical); err != nil {
		t.Fatalf("save historical job: %v", err)
	}
	historicalLoaded, err := store.GetJob(ctx, historical.ID)
	if err != nil || historicalLoaded.EngineCoverage.Status != scanrun.CoverageUnknown || len(historicalLoaded.EngineOutcomes) != 0 {
		t.Fatalf("historical job metadata = %+v err=%v, want unknown without outcomes", historicalLoaded, err)
	}
}
