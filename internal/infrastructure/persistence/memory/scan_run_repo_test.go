package memory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMemoryScanRunStore_LegacyCompatibility(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)
	store := memory.NewScanRunStore()
	now := time.Now().UTC()

	run := ports.ScanRun{
		ID:           "legacy-1",
		EngagementID: "eng-1",
		CreatedAt:    now,
		Manifest: ports.ScanManifest{
			ToolVersions: map[string]string{"syft": "v1.0.0"},
		},
		FindingKeys: []string{"k1", "k2"},
	}

	if err := store.Save(ctx, run); err != nil {
		t.Fatalf("save legacy run: %v", err)
	}

	got, err := store.Get(ctx, "legacy-1")
	if err != nil {
		t.Fatalf("get legacy run: %v", err)
	}
	if got.ID != "legacy-1" || got.Manifest.ToolVersions["syft"] != "v1.0.0" {
		t.Fatalf("unexpected legacy run: %+v", got)
	}

	list, err := store.List(ctx, "eng-1")
	if err != nil {
		t.Fatalf("list legacy runs: %v", err)
	}
	if len(list) != 1 || list[0].ID != "legacy-1" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestMemoryScanRunStore_NativeSealedProvenance(t *testing.T) {
	ctx := context.Background()
	store := memory.NewScanRunStore()
	now := time.Now().UTC()
	tenantID := shared.ID("tenant-alpha")
	engID := shared.ID("eng-alpha")

	target, err := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	if err != nil {
		t.Fatalf("canonicalize target: %v", err)
	}

	run := scanrun.ScanRun{
		TenantID:              tenantID,
		EngagementID:          engID,
		ID:                    "run-native-1",
		Provenance:            scanrun.ProvenanceNative,
		TerminalStatus:        scanrun.StatusBuilding,
		ManifestSchemaVersion: 1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if err := store.SaveScanRun(ctx, run); err != nil {
		t.Fatalf("save native scan run: %v", err)
	}
	if err := store.SaveScanRun(ctx, run); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate create must be a conflict, got %v", err)
	}
	forged := run
	forged.ID = "forged-sealed-run"
	forged.ManifestHash = strings.Repeat("0", 64)
	forged.SealedAt = &now
	if err := store.SaveScanRun(ctx, forged); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("SaveScanRun accepted a forged sealed header: %v", err)
	}
	if err := store.SealScanRun(ctx, ports.SealScanRunCommand{TenantID: tenantID, RunID: run.ID, TerminalStatus: scanrun.StatusSucceeded, ManifestSchemaVersion: 1, SealedAt: now}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("SealScanRun accepted an empty manifest: %v", err)
	}

	// 1. Query building run
	stored, err := store.GetScanRun(ctx, tenantID, "run-native-1")
	if err != nil {
		t.Fatalf("get native scan run: %v", err)
	}
	if stored.TerminalStatus != scanrun.StatusBuilding || stored.IsSealed() {
		t.Fatalf("unexpected status: %v", stored.TerminalStatus)
	}

	// 2. Seal the run with lane facts
	lane := scanrun.Lane{
		TenantID:                  tenantID,
		EngagementID:              engID,
		ScanRunID:                 "run-native-1",
		LaneKey:                   "sast-main",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		IncludedScope:             []string{"src/"},
		StartedAt:                 now,
		ManifestSchemaVersion:     1,
		Versions: []scanrun.LaneVersion{
			{VersionKind: scanrun.VersionScanner, Name: "semgrep", Version: "1.45.0"},
		},
		Stages: []scanrun.LaneStage{
			{StageKey: "eval", Status: scanrun.StageSucceeded, StartedAt: now},
		},
	}
	laneHash, err := scanrun.ComputeManifestHash(lane)
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}
	lane.ManifestHash = laneHash
	manifestHash, err := scanrun.ComputeRunManifestHash([]scanrun.Lane{lane})
	if err != nil {
		t.Fatalf("compute run hash: %v", err)
	}

	sealedAt := now.Add(time.Minute)
	err = store.SealScanRun(ctx, ports.SealScanRunCommand{TenantID: tenantID, RunID: "run-native-1", TerminalStatus: scanrun.StatusSucceeded, Lanes: []scanrun.Lane{lane}, ManifestSchemaVersion: 1, ManifestHash: manifestHash, SealedAt: sealedAt})
	if err != nil {
		t.Fatalf("seal scan run: %v", err)
	}

	// 3. Verify sealed run
	sealed, err := store.GetScanRun(ctx, tenantID, "run-native-1")
	if err != nil {
		t.Fatalf("get sealed run: %v", err)
	}
	if !sealed.IsSealed() || sealed.TerminalStatus != scanrun.StatusSucceeded || !sealed.IsCompleteCoverage() {
		t.Fatalf("expected complete coverage sealed run, got: %+v", sealed)
	}
	if len(sealed.Lanes) != 1 || sealed.Lanes[0].LaneKey != "sast-main" {
		t.Fatalf("unexpected lanes: %+v", sealed.Lanes)
	}

	// 4. Duplicate seal with same hash is idempotent no-op
	err = store.SealScanRun(ctx, ports.SealScanRunCommand{TenantID: tenantID, RunID: "run-native-1", TerminalStatus: scanrun.StatusSucceeded, Lanes: []scanrun.Lane{lane}, ManifestSchemaVersion: 1, ManifestHash: manifestHash, SealedAt: sealedAt})
	if err != nil {
		t.Fatalf("duplicate idempotent seal failed: %v", err)
	}

	// 5. Conflicting seal returns ErrConflict
	err = store.SealScanRun(ctx, ports.SealScanRunCommand{TenantID: tenantID, RunID: "run-native-1", TerminalStatus: scanrun.StatusFailed, Lanes: []scanrun.Lane{lane}, ManifestSchemaVersion: 1, ManifestHash: manifestHash, SealedAt: sealedAt})
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict on conflicting seal, got %v", err)
	}

	// 6. Post-seal mutation via SaveScanRun is rejected with ErrConflict
	err = store.SaveScanRun(ctx, run)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict updating sealed run, got %v", err)
	}

	// 7. Tenant isolation: tenant-beta cannot see tenant-alpha's run
	_, err = store.GetScanRun(ctx, "tenant-beta", "run-native-1")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant get, got %v", err)
	}
}

func TestMemoryScanRunStore_MissingTenantFailsClosed(t *testing.T) {
	store := memory.NewScanRunStore()
	now := time.Now().UTC()

	tenantA := shared.ID("tenant-a")
	tenantB := shared.ID("tenant-b")
	engA := shared.ID("eng-a")
	engB := shared.ID("eng-b")

	ctxA := shared.WithTenant(context.Background(), tenantA)
	ctxB := shared.WithTenant(context.Background(), tenantB)
	ctxNoTenant := context.Background()
	ctxDefault := shared.WithTenant(context.Background(), shared.DefaultTenant)

	// 1. Save runs under Tenant A and Tenant B
	runA := ports.ScanRun{ID: "run-a", EngagementID: string(engA), CreatedAt: now}
	runB := ports.ScanRun{ID: "run-b", EngagementID: string(engB), CreatedAt: now}

	if err := store.Save(ctxA, runA); err != nil {
		t.Fatalf("save run A: %v", err)
	}
	if err := store.Save(ctxB, runB); err != nil {
		t.Fatalf("save run B: %v", err)
	}

	// 2. Every legacy operation fails closed without an ambient tenant.
	_, err := store.Get(ctxNoTenant, "run-a")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation querying without a tenant, got %v", err)
	}
	if _, err := store.List(ctxNoTenant, engA); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation listing without a tenant, got %v", err)
	}

	// 3. The default tenant remains available only when explicitly bound.
	runDef := ports.ScanRun{ID: "run-def", EngagementID: string(engA), CreatedAt: now}
	if err := store.Save(ctxNoTenant, runDef); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation saving without a tenant, got %v", err)
	}
	if err := store.Save(ctxDefault, runDef); err != nil {
		t.Fatalf("save run def: %v", err)
	}

	gotDef, err := store.Get(ctxDefault, "run-def")
	if err != nil {
		t.Fatalf("get run def: %v", err)
	}
	if gotDef.ID != "run-def" {
		t.Fatalf("unexpected run: %+v", gotDef)
	}

	// 4. Tenant A still cannot see DefaultTenant run or Tenant B run
	_, err = store.Get(ctxA, "run-def")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for tenant A getting default run, got %v", err)
	}
	_, err = store.Get(ctxA, "run-b")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for tenant A getting tenant B run, got %v", err)
	}
}
