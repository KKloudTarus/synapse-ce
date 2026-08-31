package postgres

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresScanRunStore_LegacyCompatibility(t *testing.T) {
	ctx, pool := setupTestDB(t)
	store := NewScanRunStore(pool)

	tenantID := shared.ID(fmt.Sprintf("t-legacy-%d", time.Now().UnixNano()))
	engID := shared.ID(fmt.Sprintf("e-legacy-%d", time.Now().UnixNano()))
	runID := fmt.Sprintf("legacy-run-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)

	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, engID, "", "")

	ctxWithTenant := shared.WithTenant(ctx, tenantID)

	legacyRun := ports.ScanRun{
		ID:           runID,
		EngagementID: engID.String(),
		CreatedAt:    now,
		Manifest: ports.ScanManifest{
			ToolVersions: map[string]string{"syft": "v1.0.0"},
			ReproScore:   95,
		},
		FindingKeys: []string{"rule-1", "rule-2"},
	}

	if err := store.Save(ctxWithTenant, legacyRun); err != nil {
		t.Fatalf("save legacy scan run: %v", err)
	}

	got, err := store.Get(ctxWithTenant, runID)
	if err != nil {
		t.Fatalf("get legacy scan run: %v", err)
	}
	if got.ID != runID || got.EngagementID != engID.String() || got.Manifest.ToolVersions["syft"] != "v1.0.0" {
		t.Fatalf("unexpected legacy run: %+v", got)
	}

	list, err := store.List(ctxWithTenant, engID)
	if err != nil {
		t.Fatalf("list legacy scan runs: %v", err)
	}
	if len(list) != 1 || list[0].ID != runID {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestPostgresScanRunStore_NativeSealedProvenance(t *testing.T) {
	ctx, pool := setupTestDB(t)
	store := NewScanRunStore(pool)

	tenantID := shared.ID(fmt.Sprintf("t-native-%d", time.Now().UnixNano()))
	engID := shared.ID(fmt.Sprintf("e-native-%d", time.Now().UnixNano()))
	runID := fmt.Sprintf("run-nat-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)

	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, engID, "", "")

	target, err := scanrun.CanonicalizeRepositoryTarget("https://github.com/KKloudTarus/synapse-ce", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	if err != nil {
		t.Fatalf("canonicalize target: %v", err)
	}

	run := scanrun.ScanRun{
		TenantID:              tenantID,
		EngagementID:          engID,
		ID:                    runID,
		Provenance:            scanrun.ProvenanceNative,
		TerminalStatus:        scanrun.StatusBuilding,
		ManifestSchemaVersion: 1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	// 1. Save native building run
	if err := store.SaveScanRun(ctx, run); err != nil {
		t.Fatalf("save scan run: %v", err)
	}

	stored, err := store.GetScanRun(ctx, tenantID, runID)
	if err != nil {
		t.Fatalf("get scan run: %v", err)
	}
	if stored.TerminalStatus != scanrun.StatusBuilding || stored.IsSealed() {
		t.Fatalf("unexpected stored run state: %+v", stored)
	}

	// 2. Prepare lane and seal
	lane := scanrun.Lane{
		TenantID:                  tenantID,
		EngagementID:              engID,
		ScanRunID:                 runID,
		LaneKey:                   "sast-lane",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		IncludedScope:             []string{"src/"},
		ExcludedScope:             []string{"vendor/"},
		StartedAt:                 now,
		FinishedAt:                &now,
		ResultSHA256:              "sha-12345",
		ManifestSchemaVersion:     1,
		Versions: []scanrun.LaneVersion{
			{VersionKind: scanrun.VersionScanner, Name: "semgrep", Version: "1.45.0"},
			{VersionKind: scanrun.VersionRulePack, Name: "default", Version: "2026.08"},
		},
		Stages: []scanrun.LaneStage{
			{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: now, FinishedAt: &now},
		},
	}
	manifestHash, err := scanrun.ComputeManifestHash(lane)
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}
	lane.ManifestHash = manifestHash

	sealedAt := now.Add(time.Minute)
	if err := store.SealScanRun(ctx, tenantID, runID, scanrun.StatusSucceeded, []scanrun.Lane{lane}, 1, manifestHash, sealedAt); err != nil {
		t.Fatalf("seal scan run: %v", err)
	}

	// 3. Verify sealed run
	sealed, err := store.GetScanRun(ctx, tenantID, runID)
	if err != nil {
		t.Fatalf("get sealed run: %v", err)
	}
	if !sealed.IsSealed() || sealed.TerminalStatus != scanrun.StatusSucceeded || !sealed.IsCompleteCoverage() {
		t.Fatalf("expected complete coverage sealed run, got: %+v", sealed)
	}
	if len(sealed.Lanes) != 1 || len(sealed.Lanes[0].Versions) != 2 || len(sealed.Lanes[0].Stages) != 1 {
		t.Fatalf("unexpected lanes: %+v", sealed.Lanes)
	}

	// 4. Duplicate idempotent seal succeeds
	if err := store.SealScanRun(ctx, tenantID, runID, scanrun.StatusSucceeded, []scanrun.Lane{lane}, 1, manifestHash, sealedAt); err != nil {
		t.Fatalf("duplicate idempotent seal: %v", err)
	}

	// 5. Conflicting seal fails with ErrConflict
	err = store.SealScanRun(ctx, tenantID, runID, scanrun.StatusFailed, []scanrun.Lane{lane}, 1, "different-hash", sealedAt)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict on conflicting seal, got %v", err)
	}

	// 6. Direct update after seal fails with ErrConflict
	err = store.SaveScanRun(ctx, run)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict updating sealed run, got %v", err)
	}
}

func TestPostgresScanRunStore_ConcurrentSealing(t *testing.T) {
	ctx, pool := setupTestDB(t)
	store := NewScanRunStore(pool)

	tenantID := shared.ID(fmt.Sprintf("t-conc-%d", time.Now().UnixNano()))
	engID := shared.ID(fmt.Sprintf("e-conc-%d", time.Now().UnixNano()))
	runID := fmt.Sprintf("run-conc-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)

	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, engID, "", "")

	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")

	run := scanrun.ScanRun{
		TenantID:              tenantID,
		EngagementID:          engID,
		ID:                    runID,
		Provenance:            scanrun.ProvenanceNative,
		TerminalStatus:        scanrun.StatusBuilding,
		ManifestSchemaVersion: 1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if err := store.SaveScanRun(ctx, run); err != nil {
		t.Fatalf("save scan run: %v", err)
	}

	lane1 := scanrun.Lane{
		TenantID:                  tenantID,
		EngagementID:              engID,
		ScanRunID:                 runID,
		LaneKey:                   "lane-1",
		Producer:                  "producer-1",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     1,
		ManifestHash:              "hash-winner-1",
	}

	lane2 := scanrun.Lane{
		TenantID:                  tenantID,
		EngagementID:              engID,
		ScanRunID:                 runID,
		LaneKey:                   "lane-2",
		Producer:                  "producer-2",
		TerminalStatus:            scanrun.StatusFailed,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"dast_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     1,
		ManifestHash:              "hash-winner-2",
	}

	var wg sync.WaitGroup
	results := make([]error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		results[0] = store.SealScanRun(ctx, tenantID, runID, scanrun.StatusSucceeded, []scanrun.Lane{lane1}, 1, "hash-winner-1", now)
	}()
	go func() {
		defer wg.Done()
		results[1] = store.SealScanRun(ctx, tenantID, runID, scanrun.StatusFailed, []scanrun.Lane{lane2}, 1, "hash-winner-2", now)
	}()

	wg.Wait()

	// Exactly one writer must succeed, and the other must receive ErrConflict
	successCount := 0
	conflictCount := 0
	for _, res := range results {
		if res == nil {
			successCount++
		} else if errors.Is(res, shared.ErrConflict) {
			conflictCount++
		} else {
			t.Errorf("unexpected concurrent seal result: %v", res)
		}
	}

	if successCount != 1 || conflictCount != 1 {
		t.Fatalf("expected exactly 1 success and 1 conflict, got success=%d, conflict=%d", successCount, conflictCount)
	}
}

func TestPostgresScanRunStore_UnprivilegedRoleRLS(t *testing.T) {
	ctx, pool := setupTestDB(t)
	store := NewScanRunStore(pool)

	tenantA := shared.ID(fmt.Sprintf("t-rls-a-%d", time.Now().UnixNano()))
	tenantB := shared.ID(fmt.Sprintf("t-rls-b-%d", time.Now().UnixNano()))
	engA := shared.ID(fmt.Sprintf("e-rls-a-%d", time.Now().UnixNano()))
	engB := shared.ID(fmt.Sprintf("e-rls-b-%d", time.Now().UnixNano()))
	runA := fmt.Sprintf("run-rls-a-%d", time.Now().UnixNano())

	ensureTestTenantAndEngagement(t, ctx, pool, tenantA, engA, "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantB, engB, "", "")

	// Create dedicated unprivileged test role
	const unprivRole = "synapse_scanrun_rls_test"
	cleanupRole := func() {
		_, _ = pool.Exec(ctx, `DROP OWNED BY `+unprivRole)
		_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+unprivRole)
	}
	cleanupRole()
	t.Cleanup(func() { cleanupRole() })

	if _, err := pool.Exec(ctx, `CREATE ROLE `+unprivRole+` NOLOGIN NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create unprivileged test role: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+unprivRole); err != nil {
		t.Fatalf("grant schema usage: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO `+unprivRole); err != nil {
		t.Fatalf("grant table privileges: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	run := scanrun.ScanRun{
		TenantID:              tenantA,
		EngagementID:          engA,
		ID:                    runA,
		Provenance:            scanrun.ProvenanceNative,
		TerminalStatus:        scanrun.StatusBuilding,
		ManifestSchemaVersion: 1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	// 1. Insert run under tenant A using unprivileged role
	err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+unprivRole); err != nil {
			return err
		}
		return store.SaveScanRun(ctx, run)
	})
	if err != nil {
		t.Fatalf("save scan run under unprivileged role: %v", err)
	}

	// 2. Read under tenant A works
	err = WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+unprivRole); err != nil {
			return err
		}
		got, err := store.GetScanRun(ctx, tenantA, runA)
		if err != nil {
			return err
		}
		if got.ID != runA {
			return fmt.Errorf("id mismatch: got %s, want %s", got.ID, runA)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read scan run under tenant A: %v", err)
	}

	// 3. Read under tenant B fails with ErrNotFound (RLS blocks row visibility)
	err = WithTenant(ctx, pool, tenantB.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+unprivRole); err != nil {
			return err
		}
		_, err := store.GetScanRun(ctx, tenantB, runA)
		return err
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant get under unprivileged role, got %v", err)
	}
}

func TestPostgresScanRunStore_TimestampMicrosecondEquality(t *testing.T) {
	ctx, pool := setupTestDB(t)
	store := NewScanRunStore(pool)

	tenantID := shared.ID(fmt.Sprintf("t-ts-%d", time.Now().UnixNano()))
	engID := shared.ID(fmt.Sprintf("e-ts-%d", time.Now().UnixNano()))
	runID := fmt.Sprintf("run-ts-%d", time.Now().UnixNano())

	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, engID, "", "")

	// Microsecond truncated timestamp
	now := time.Now().UTC().Truncate(time.Microsecond)

	run := scanrun.ScanRun{
		TenantID:              tenantID,
		EngagementID:          engID,
		ID:                    runID,
		Provenance:            scanrun.ProvenanceNative,
		TerminalStatus:        scanrun.StatusBuilding,
		ManifestSchemaVersion: 1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if err := store.SaveScanRun(ctx, run); err != nil {
		t.Fatalf("save scan run: %v", err)
	}

	got, err := store.GetScanRun(ctx, tenantID, runID)
	if err != nil {
		t.Fatalf("get scan run: %v", err)
	}

	if !got.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt timestamp mismatch: got %v, want %v", got.CreatedAt, now)
	}
}

func TestPostgresScanRunStore_SealValidationParity(t *testing.T) {
	ctx, pool := setupTestDB(t)
	store := NewScanRunStore(pool)

	tenantID := shared.ID(fmt.Sprintf("t-val-%d", time.Now().UnixNano()))
	engID := shared.ID(fmt.Sprintf("e-val-%d", time.Now().UnixNano()))
	runID := fmt.Sprintf("run-val-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)

	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, engID, "", "")

	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	lane := scanrun.Lane{
		TenantID:                  tenantID,
		EngagementID:              engID,
		ScanRunID:                 runID,
		LaneKey:                   "sast-lane",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     scanrun.CurrentManifestSchemaVersion,
		ManifestHash:              "hash1",
	}

	// 1. StatusBuilding is not terminal -> ErrValidation
	err := store.SealScanRun(ctx, tenantID, runID, scanrun.StatusBuilding, []scanrun.Lane{lane}, 1, "hash1", now)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation when sealing with StatusBuilding, got %v", err)
	}

	// 2. Zero sealedAt timestamp -> ErrValidation
	err = store.SealScanRun(ctx, tenantID, runID, scanrun.StatusSucceeded, []scanrun.Lane{lane}, 1, "hash1", time.Time{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation when sealing with zero sealedAt, got %v", err)
	}
}

func TestPostgresScanRunStore_ResealIdempotencyAndReproducibility(t *testing.T) {
	ctx, pool := setupTestDB(t)
	store := NewScanRunStore(pool)

	tenantID := shared.ID(fmt.Sprintf("t-reseal-%d", time.Now().UnixNano()))
	engID := shared.ID(fmt.Sprintf("e-reseal-%d", time.Now().UnixNano()))
	runID := fmt.Sprintf("run-reseal-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)

	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, engID, "", "")

	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")

	run := scanrun.ScanRun{
		TenantID:              tenantID,
		EngagementID:          engID,
		ID:                    runID,
		Provenance:            scanrun.ProvenanceNative,
		TerminalStatus:        scanrun.StatusBuilding,
		ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if err := store.SaveScanRun(ctx, run); err != nil {
		t.Fatalf("save building scan run: %v", err)
	}

	laneA := scanrun.Lane{
		TenantID:                  tenantID,
		EngagementID:              engID,
		ScanRunID:                 runID,
		LaneKey:                   "lane-a",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     scanrun.CurrentManifestSchemaVersion,
	}
	hashA, err := scanrun.ComputeManifestHash(laneA)
	if err != nil {
		t.Fatalf("compute hash A: %v", err)
	}
	laneA.ManifestHash = hashA

	laneB := scanrun.Lane{
		TenantID:                  tenantID,
		EngagementID:              engID,
		ScanRunID:                 runID,
		LaneKey:                   "lane-b",
		Producer:                  "synapse-sca",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"dep_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     scanrun.CurrentManifestSchemaVersion,
	}
	hashB, err := scanrun.ComputeManifestHash(laneB)
	if err != nil {
		t.Fatalf("compute hash B: %v", err)
	}
	laneB.ManifestHash = hashB

	aggregateHash, err := scanrun.ComputeRunManifestHash([]scanrun.Lane{laneA, laneB})
	if err != nil {
		t.Fatalf("compute aggregate hash: %v", err)
	}

	// 1. First seal using [laneA, laneB] order
	if err := store.SealScanRun(ctx, tenantID, runID, scanrun.StatusSucceeded, []scanrun.Lane{laneA, laneB}, scanrun.CurrentManifestSchemaVersion, aggregateHash, now); err != nil {
		t.Fatalf("first seal: %v", err)
	}

	// 2. Second seal using [laneB, laneA] reverse order -> MUST be idempotent success, NOT ErrConflict
	if err := store.SealScanRun(ctx, tenantID, runID, scanrun.StatusSucceeded, []scanrun.Lane{laneB, laneA}, scanrun.CurrentManifestSchemaVersion, aggregateHash, now); err != nil {
		t.Fatalf("re-seal with reordered lanes must be idempotent success: %v", err)
	}

	// 3. Load from database and assert reproducibility
	loaded, err := store.GetScanRun(ctx, tenantID, runID)
	if err != nil {
		t.Fatalf("get sealed scan run: %v", err)
	}

	if loaded.ManifestHash != aggregateHash {
		t.Fatalf("stored manifest hash mismatch: got %q, want %q", loaded.ManifestHash, aggregateHash)
	}

	recomputedHash, err := scanrun.ComputeRunManifestHash(loaded.Lanes)
	if err != nil {
		t.Fatalf("recompute hash from loaded lanes: %v", err)
	}

	if recomputedHash != loaded.ManifestHash {
		t.Fatalf("persisted lanes recomputation %q does not match stored manifest hash %q", recomputedHash, loaded.ManifestHash)
	}
}

func TestPostgresScanRunStore_DirectSQLTriggerDefense(t *testing.T) {
	ctx, pool := setupTestDB(t)
	store := NewScanRunStore(pool)

	tenantA := shared.ID(fmt.Sprintf("t-trig-a-%d", time.Now().UnixNano()))
	tenantB := shared.ID(fmt.Sprintf("t-trig-b-%d", time.Now().UnixNano()))
	engA := shared.ID(fmt.Sprintf("e-trig-a-%d", time.Now().UnixNano()))
	engB := shared.ID(fmt.Sprintf("e-trig-b-%d", time.Now().UnixNano()))
	runID := fmt.Sprintf("run-trig-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)

	ensureTestTenantAndEngagement(t, ctx, pool, tenantA, engA, "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantB, engB, "", "")

	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")

	// Phase 1: Unsealed run allows pre-seal insertions and updates
	run := scanrun.ScanRun{
		TenantID:              tenantA,
		EngagementID:          engA,
		ID:                    runID,
		Provenance:            scanrun.ProvenanceNative,
		TerminalStatus:        scanrun.StatusBuilding,
		ManifestSchemaVersion: 1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if err := store.SaveScanRun(ctx, run); err != nil {
		t.Fatalf("save building scan run: %v", err)
	}

	lane := scanrun.Lane{
		TenantID:                  tenantA,
		EngagementID:              engA,
		ScanRunID:                 runID,
		LaneKey:                   "sast-lane",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     1,
		ManifestHash:              "hash1",
		Versions: []scanrun.LaneVersion{
			{VersionKind: scanrun.VersionScanner, Name: "semgrep", Version: "1.45.0"},
		},
		Stages: []scanrun.LaneStage{
			{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: now},
		},
	}
	if err := store.SealScanRun(ctx, tenantA, runID, scanrun.StatusSucceeded, []scanrun.Lane{lane}, 1, "hash1", now); err != nil {
		t.Fatalf("seal scan run: %v", err)
	}

	// Phase 2: Parent UPDATE protection on every candidate field
	parentUpdateCases := []struct {
		name  string
		query string
	}{
		{"tenant_id", fmt.Sprintf(`UPDATE scan_runs SET tenant_id = '%s' WHERE tenant_id = '%s' AND id = '%s'`, tenantB.String(), tenantA.String(), runID)},
		{"engagement_id", fmt.Sprintf(`UPDATE scan_runs SET engagement_id = 'other-eng' WHERE tenant_id = '%s' AND id = '%s'`, tenantA.String(), runID)},
		{"terminal_status", fmt.Sprintf(`UPDATE scan_runs SET terminal_status = 'failed' WHERE tenant_id = '%s' AND id = '%s'`, tenantA.String(), runID)},
		{"provenance", fmt.Sprintf(`UPDATE scan_runs SET provenance = 'legacy' WHERE tenant_id = '%s' AND id = '%s'`, tenantA.String(), runID)},
		{"manifest_schema_version", fmt.Sprintf(`UPDATE scan_runs SET manifest_schema_version = 2 WHERE tenant_id = '%s' AND id = '%s'`, tenantA.String(), runID)},
		{"manifest_hash", fmt.Sprintf(`UPDATE scan_runs SET manifest_hash = 'tampered-hash' WHERE tenant_id = '%s' AND id = '%s'`, tenantA.String(), runID)},
		{"sealed_at", fmt.Sprintf(`UPDATE scan_runs SET sealed_at = '%s' WHERE tenant_id = '%s' AND id = '%s'`, now.Add(time.Hour).Format(time.RFC3339Nano), tenantA.String(), runID)},
		{"updated_at", fmt.Sprintf(`UPDATE scan_runs SET updated_at = '%s' WHERE tenant_id = '%s' AND id = '%s'`, now.Add(time.Hour).Format(time.RFC3339Nano), tenantA.String(), runID)},
	}

	for _, tc := range parentUpdateCases {
		t.Run("parent_update_"+tc.name, func(t *testing.T) {
			err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, tc.query)
				return err
			})
			if err == nil {
				t.Fatalf("expected DB trigger to reject direct UPDATE on field %s of sealed scan_runs header", tc.name)
			}
		})
	}

	// Phase 3: Parent DELETE protection
	t.Run("parent_delete_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM scan_runs WHERE tenant_id = $1 AND id = $2`, tenantA.String(), runID)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct DELETE on sealed scan_runs header")
		}

		// Verify parent and child rows still exist
		got, err := store.GetScanRun(ctx, tenantA, runID)
		if err != nil {
			t.Fatalf("get scan run after failed delete: %v", err)
		}
		if got.ID != runID || len(got.Lanes) != 1 {
			t.Fatalf("sealed scan run was corrupted by delete attempt: %+v", got)
		}
	})

	// Phase 4: Child INSERT attacks after seal
	t.Run("child_insert_lanes_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO scan_run_lanes (
					tenant_id, engagement_id, scan_run_id, lane_key, producer,
					terminal_status, target_kind, target_identity_schema_version,
					target_identity_canonical, evaluated_revision,
					authoritative_finding_kinds, included_scope, excluded_scope,
					started_at, created_at
				) VALUES (
					$1, $2, $3, 'injected-lane', 'injected-producer',
					'succeeded', 'repository', 1,
					'https://github.com/org/repo', 'e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04',
					'[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
					$4, $4
				)
			`, tenantA.String(), engA.String(), runID, now)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct INSERT on scan_run_lanes for sealed scan run")
		}
	})

	t.Run("child_insert_versions_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO scan_run_lane_versions (
					tenant_id, scan_run_id, lane_key, version_kind, name, version
				) VALUES ($1, $2, 'sast-lane', 'tool', 'injected-tool', '1.0.0')
			`, tenantA.String(), runID)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct INSERT on scan_run_lane_versions for sealed scan run")
		}
	})

	t.Run("child_insert_stages_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO scan_run_lane_stages (
					tenant_id, scan_run_id, lane_key, stage_key, status, started_at
				) VALUES ($1, $2, 'sast-lane', 'injected-stage', 'succeeded', $3)
			`, tenantA.String(), runID, now)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct INSERT on scan_run_lane_stages for sealed scan run")
		}
	})

	// Phase 5: Child UPDATE attacks after seal
	t.Run("child_update_lanes_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE scan_run_lanes SET producer = 'hacked' WHERE tenant_id = $1 AND scan_run_id = $2`, tenantA.String(), runID)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct UPDATE on scan_run_lanes for sealed scan run")
		}
	})

	t.Run("child_update_versions_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE scan_run_lane_versions SET version = '9.9.9' WHERE tenant_id = $1 AND scan_run_id = $2`, tenantA.String(), runID)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct UPDATE on scan_run_lane_versions for sealed scan run")
		}
	})

	t.Run("child_update_stages_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE scan_run_lane_stages SET status = 'failed' WHERE tenant_id = $1 AND scan_run_id = $2`, tenantA.String(), runID)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct UPDATE on scan_run_lane_stages for sealed scan run")
		}
	})

	// Phase 6: Child DELETE attacks after seal
	t.Run("child_delete_stages_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM scan_run_lane_stages WHERE tenant_id = $1 AND scan_run_id = $2`, tenantA.String(), runID)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct DELETE on scan_run_lane_stages for sealed scan run")
		}
	})

	t.Run("child_delete_versions_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM scan_run_lane_versions WHERE tenant_id = $1 AND scan_run_id = $2`, tenantA.String(), runID)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct DELETE on scan_run_lane_versions for sealed scan run")
		}
	})

	t.Run("child_delete_lanes_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM scan_run_lanes WHERE tenant_id = $1 AND scan_run_id = $2`, tenantA.String(), runID)
			return err
		})
		if err == nil {
			t.Fatal("expected DB trigger to reject direct DELETE on scan_run_lanes for sealed scan run")
		}
	})

	// Phase 7: Cross-tenant direct SQL attacks by Tenant B
	t.Run("cross_tenant_insert_child_blocked", func(t *testing.T) {
		err := WithTenant(ctx, pool, tenantB.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO scan_run_lanes (
					tenant_id, engagement_id, scan_run_id, lane_key, producer,
					terminal_status, target_kind, target_identity_schema_version,
					target_identity_canonical, evaluated_revision,
					authoritative_finding_kinds, included_scope, excluded_scope,
					started_at, created_at
				) VALUES (
					$1, $2, $3, 'b-injected', 'b-producer',
					'succeeded', 'repository', 1,
					'https://github.com/org/repo', 'e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04',
					'[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
					$4, $4
				)
			`, tenantB.String(), engB.String(), runID, now)
			return err
		})
		if err == nil {
			t.Fatal("expected cross-tenant FK constraint or trigger to reject foreign scan_run_id reference")
		}
	})

	t.Run("cross_tenant_delete_parent_blocked", func(t *testing.T) {
		_ = WithTenant(ctx, pool, tenantB.String(), func(tx pgx.Tx) error {
			res, err := tx.Exec(ctx, `DELETE FROM scan_runs WHERE id = $1`, runID)
			if err != nil {
				return err // Trigger blocked the delete
			}
			if res.RowsAffected() > 0 {
				t.Fatalf("cross-tenant delete affected %d rows", res.RowsAffected())
			}
			return nil
		})

		// Ensure A's run still exists unharmed
		got, err := store.GetScanRun(ctx, tenantA, runID)
		if err != nil || got.ID != runID {
			t.Fatalf("tenant A run was deleted or corrupted by cross-tenant query: %v", err)
		}
	})
}
