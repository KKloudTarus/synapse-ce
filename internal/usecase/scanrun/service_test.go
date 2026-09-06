package scanrun_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
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
	seen    map[string]struct{}
	err     error
}

func (a *recordAudit) Record(_ context.Context, e ports.AuditEntry) error {
	if a.err != nil {
		return a.err
	}
	a.entries = append(a.entries, e)
	return nil
}

func (a *recordAudit) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	if a.err != nil {
		return a.err
	}
	key := e.Metadata["idempotency_key"]
	if _, ok := a.seen[key]; ok {
		return nil
	}
	a.seen[key] = struct{}{}
	return a.Record(ctx, e)
}

func setupServiceTest(t *testing.T) (*uc.Service, *memory.ScanRunStore, *memory.EngagementRepository, *recordAudit) {
	t.Helper()
	runStore := memory.NewScanRunStore()
	engRepo := memory.NewEngagementRepository()
	txRunner := memory.NewTenantTransactionRunner()
	clock := fixedClock{t: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}
	idGen := &seqIDGen{}
	audit := &recordAudit{seen: make(map[string]struct{})}

	svc, err := uc.NewService(runStore, engRepo, txRunner, idGen, clock, audit)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, runStore, engRepo, audit
}

func TestNewService_RequiresEveryDependency(t *testing.T) {
	runs := memory.NewScanRunStore()
	engagements := memory.NewEngagementRepository()
	tx := memory.NewTenantTransactionRunner()
	ids := &seqIDGen{}
	clock := fixedClock{t: time.Now()}
	audit := &recordAudit{seen: make(map[string]struct{})}

	tests := []struct {
		name string
		new  func() (*uc.Service, error)
	}{
		{"runs", func() (*uc.Service, error) { return uc.NewService(nil, engagements, tx, ids, clock, audit) }},
		{"engagements", func() (*uc.Service, error) { return uc.NewService(runs, nil, tx, ids, clock, audit) }},
		{"transaction runner", func() (*uc.Service, error) { return uc.NewService(runs, engagements, nil, ids, clock, audit) }},
		{"id generator", func() (*uc.Service, error) { return uc.NewService(runs, engagements, tx, nil, clock, audit) }},
		{"clock", func() (*uc.Service, error) { return uc.NewService(runs, engagements, tx, ids, nil, audit) }},
		{"audit", func() (*uc.Service, error) { return uc.NewService(runs, engagements, tx, ids, clock, nil) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.new(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("missing dependency accepted: %v", err)
			}
		})
	}
}

func TestService_RequiresAttributableActor(t *testing.T) {
	svc, _, _, _ := setupServiceTest(t)
	if _, err := svc.CreateNativeScanRun(context.Background(), uc.CreateNativeScanRunInput{
		TenantID: "tenant", EngagementID: "engagement", Actor: "  ",
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank create actor accepted: %v", err)
	}
	if _, err := svc.SealScanRun(context.Background(), uc.SealScanRunInput{
		TenantID: "tenant", RunID: "run", TerminalStatus: scanrun.StatusSucceeded,
		Lanes: []scanrun.Lane{{}}, Actor: "\t",
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank seal actor accepted: %v", err)
	}
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

	// An identical retry is a no-op in both provenance state and audit history.
	if _, err := svc.SealScanRun(ctx, uc.SealScanRunInput{
		TenantID: tenantID, RunID: run.ID, TerminalStatus: scanrun.StatusSucceeded,
		Lanes: []scanrun.Lane{lane}, Actor: "alice",
	}); err != nil {
		t.Fatalf("idempotent re-seal: %v", err)
	}
	if len(audit.entries) != 2 {
		t.Fatalf("idempotent re-seal appended audit entry: %+v", audit.entries)
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
	if audit.entries[2].Metadata["reason"] != "seal_conflict" || audit.entries[2].Metadata["error"] != "" {
		t.Errorf("conflict audit must contain only a stable reason code: %+v", audit.entries[2].Metadata)
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
	audit := &recordAudit{seen: make(map[string]struct{})}

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

func TestService_PostgresAuditFailureRollsBackCreate(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres atomicity test")
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

	tenantID := shared.ID(fmt.Sprintf("t-audit-fail-%d", time.Now().UnixNano()))
	engID := shared.ID(fmt.Sprintf("e-audit-fail-%d", time.Now().UnixNano()))
	_, _ = pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT DO NOTHING`, tenantID.String())
	engRepo := postgres.NewEngagementRepository(pool)
	eng, _ := engagement.New(engID, tenantID, "audit failure", "", time.Now())
	if err := engRepo.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}

	runStore := postgres.NewScanRunStore(pool)
	svc, err := uc.NewService(
		runStore,
		engRepo,
		postgres.NewTenantTransactionRunner(pool),
		&seqIDGen{},
		fixedClock{t: time.Now()},
		&recordAudit{seen: make(map[string]struct{}), err: errors.New("audit unavailable")},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.CreateNativeScanRun(ctx, uc.CreateNativeScanRunInput{
		TenantID: tenantID, EngagementID: engID, RunID: "run-audit-fail", Actor: "alice",
	})
	if err == nil || !strings.Contains(err.Error(), "audit unavailable") {
		t.Fatalf("create did not propagate audit failure: %v", err)
	}
	if _, err := runStore.GetScanRun(ctx, tenantID, "run-audit-fail"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("scan run committed without its audit record: %v", err)
	}
}
