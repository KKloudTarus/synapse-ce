package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMigration0158EvidenceImmutabilityTenantBindingAndRollback(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 158); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ensureScanRunTenantAndEngagement(t, ctx, pool, "evidence-tenant", "assessment")
	store := NewScanRunStore(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	run := scanrun.ScanRun{TenantID: "evidence-tenant", EngagementID: "assessment", ID: "evidence-run", Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding, ManifestSchemaVersion: 1, CreatedAt: now, UpdatedAt: now}
	payload := []byte(`{"version":1,"records":[]}`)
	hash := sha256.Sum256(payload)
	evidence := ports.ScanRunEvidence{TenantID: run.TenantID, RunID: run.ID, Payload: payload, ContentHash: hex.EncodeToString(hash[:])}
	failure := errors.New("audit unavailable")
	if err := NewTenantTransactionRunner(pool).Run(ctx, run.TenantID, func(txCtx context.Context) error {
		if err := store.SaveScanRun(txCtx, run); err != nil {
			return err
		}
		if err := store.SaveScanRunEvidence(txCtx, evidence); err != nil {
			return err
		}
		return failure
	}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := store.GetScanRunEvidence(ctx, run.TenantID, run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("evidence survived rollback: %v", err)
	}
	if err := store.SaveScanRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.SaveScanRunEvidence(ctx, evidence); err != nil {
			t.Fatalf("save/replay: %v", err)
		}
	}
	if _, err := store.GetScanRunEvidence(ctx, "other", run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant evidence read: %v", err)
	}
	bad := evidence
	bad.Payload = []byte(`{"version":2}`)
	if err := store.SaveScanRunEvidence(ctx, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("hash mismatch accepted: %v", err)
	}
	badHash := sha256.Sum256(bad.Payload)
	bad.ContentHash = hex.EncodeToString(badHash[:])
	if err := store.SaveScanRunEvidence(ctx, bad); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("different replay accepted: %v", err)
	}
	for _, statement := range []string{
		`UPDATE scan_run_comparison_evidence SET payload='changed' WHERE run_id='evidence-run'`,
		`DELETE FROM scan_run_comparison_evidence WHERE run_id='evidence-run'`,
	} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Fatalf("immutable evidence changed: %s", statement)
		}
	}
	var enabled, forced bool
	if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='scan_run_comparison_evidence'::regclass`).Scan(&enabled, &forced); err != nil || !enabled || !forced {
		t.Fatalf("RLS not enforced: %v %v %v", enabled, forced, err)
	}
	if err := goose.DownTo(db, ".", 157); err == nil || !strings.Contains(err.Error(), "evidence exists") {
		t.Fatalf("unsafe evidence rollback: %v", err)
	}
}
