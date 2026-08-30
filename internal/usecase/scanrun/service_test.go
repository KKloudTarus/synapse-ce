package scanrun_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	uc "github.com/KKloudTarus/synapse-ce/internal/usecase/scanrun"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDGen struct{ next int }

func (g *seqIDGen) NewID() shared.ID {
	g.next++
	return shared.ID("gen-run-" + string(rune('0'+g.next)))
}

type recordAudit struct {
	entries []ports.AuditEntry
}

func (a *recordAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

func setupServiceTest(t *testing.T) (*uc.Service, *memory.ScanRunStore, *memory.EngagementRepository, *recordAudit) {
	t.Helper()
	runStore := memory.NewScanRunStore()
	engRepo := memory.NewEngagementRepository()
	txRunner := memory.NewTenantTransactionRunner()
	clock := fixedClock{t: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}
	idGen := &seqIDGen{}
	audit := &recordAudit{}

	svc, err := uc.NewService(runStore, engRepo, txRunner, idGen, clock, audit)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, runStore, engRepo, audit
}

func TestService_CreateAndSealNativeScanRun(t *testing.T) {
	ctx := context.Background()
	svc, _, engRepo, audit := setupServiceTest(t)

	tenantID := shared.ID("t1")
	engID := shared.ID("e1")
	eng, _ := engagement.New(engID, tenantID, "Eng 1", "", time.Now())
	_ = engRepo.Create(ctx, eng)

	// 1. Create native scan run in building state
	run, err := svc.CreateNativeScanRun(ctx, uc.CreateNativeScanRunInput{
		TenantID:     tenantID,
		EngagementID: engID,
		Actor:        "alice",
	})
	if err != nil {
		t.Fatalf("create native scan run: %v", err)
	}
	if run.ID != "gen-run-1" || run.Provenance != scanrun.ProvenanceNative || run.TerminalStatus != scanrun.StatusBuilding {
		t.Fatalf("unexpected run: %+v", run)
	}

	// 2. Prepare lane facts
	target, err := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	if err != nil {
		t.Fatalf("canonicalize target: %v", err)
	}
	lane := scanrun.Lane{
		EngagementID:              engID,
		LaneKey:                   "sast-lane",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		IncludedScope:             []string{"src/"},
		StartedAt:                 time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC),
		Versions: []scanrun.LaneVersion{
			{VersionKind: scanrun.VersionScanner, Name: "semgrep", Version: "1.45.0"},
		},
		Stages: []scanrun.LaneStage{
			{StageKey: "sast_scan", Status: scanrun.StageSucceeded, StartedAt: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)},
		},
	}

	// 3. Seal the scan run
	sealed, err := svc.SealScanRun(ctx, uc.SealScanRunInput{
		TenantID:       tenantID,
		RunID:          run.ID,
		TerminalStatus: scanrun.StatusSucceeded,
		Lanes:          []scanrun.Lane{lane},
		Actor:          "alice",
	})
	if err != nil {
		t.Fatalf("seal scan run: %v", err)
	}

	if !sealed.IsSealed() || !sealed.IsCompleteCoverage() {
		t.Fatalf("expected sealed complete coverage run, got %+v", sealed)
	}
	if len(sealed.Lanes) != 1 || sealed.Lanes[0].ManifestHash == "" {
		t.Fatalf("expected computed manifest hash in sealed lane, got %+v", sealed.Lanes)
	}

	// 4. Verify audit entries
	if len(audit.entries) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(audit.entries))
	}
	if audit.entries[0].Action != "scan_run.provenance_created" || audit.entries[1].Action != "scan_run.provenance_sealed" {
		t.Errorf("unexpected audit actions: %+v", audit.entries)
	}

	// 5. Conflicting seal attempt logs conflict audit
	_, err = svc.SealScanRun(ctx, uc.SealScanRunInput{
		TenantID:       tenantID,
		RunID:          run.ID,
		TerminalStatus: scanrun.StatusFailed,
		Lanes:          []scanrun.Lane{lane},
		Actor:          "alice",
	})
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict on conflicting seal, got %v", err)
	}
	if len(audit.entries) != 3 || audit.entries[2].Action != "scan_run.provenance_conflict" {
		t.Errorf("expected conflict audit entry, got %+v", audit.entries)
	}
}

func TestService_PostgresParity(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres parity test")
	}
	ctx := context.Background()
	if err := postgres.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := postgres.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	runStore := postgres.NewScanRunStore(pool)
	engRepo := postgres.NewEngagementRepository(pool)
	txRunner := postgres.NewTenantTransactionRunner(pool)
	clock := fixedClock{t: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}
	idGen := &seqIDGen{}
	audit := &recordAudit{}

	svc, err := uc.NewService(runStore, engRepo, txRunner, idGen, clock, audit)
	if err != nil {
		t.Fatalf("new service with postgres: %v", err)
	}

	tenantID := shared.ID(fmt.Sprintf("t-parity-%d", time.Now().UnixNano()))
	engID := shared.ID(fmt.Sprintf("e-parity-%d", time.Now().UnixNano()))

	_, _ = pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, tenantID.String(), "Tenant")
	eng, _ := engagement.New(engID, tenantID, "Eng Parity", "", time.Now())
	_ = engRepo.Create(ctx, eng)

	// 1. Create native scan run
	run, err := svc.CreateNativeScanRun(ctx, uc.CreateNativeScanRunInput{
		TenantID:     tenantID,
		EngagementID: engID,
		Actor:        "alice",
	})
	if err != nil {
		t.Fatalf("create native run via postgres: %v", err)
	}

	// 2. Prepare lane & seal
	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	lane := scanrun.Lane{
		EngagementID:              engID,
		LaneKey:                   "sast-lane",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		IncludedScope:             []string{"src/"},
		StartedAt:                 time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC),
		Versions: []scanrun.LaneVersion{
			{VersionKind: scanrun.VersionScanner, Name: "semgrep", Version: "1.45.0"},
		},
		Stages: []scanrun.LaneStage{
			{StageKey: "sast_scan", Status: scanrun.StageSucceeded, StartedAt: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)},
		},
	}

	sealed, err := svc.SealScanRun(ctx, uc.SealScanRunInput{
		TenantID:       tenantID,
		RunID:          run.ID,
		TerminalStatus: scanrun.StatusSucceeded,
		Lanes:          []scanrun.Lane{lane},
		Actor:          "alice",
	})
	if err != nil {
		t.Fatalf("seal native run via postgres: %v", err)
	}

	if !sealed.IsSealed() || !sealed.IsCompleteCoverage() {
		t.Fatalf("expected sealed complete coverage run from postgres, got %+v", sealed)
	}

	// 3. Query through service
	got, err := svc.GetScanRun(ctx, tenantID, run.ID)
	if err != nil {
		t.Fatalf("get scan run: %v", err)
	}
	if got.ID != run.ID || len(got.Lanes) != 1 {
		t.Fatalf("unexpected fetched run: %+v", got)
	}
}
