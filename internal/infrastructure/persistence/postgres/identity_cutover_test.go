package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestIdentityCutoverDeclaresOnlyCleanCurrentShadowAndRefusesAbort(t *testing.T) {
	f := newIdentityFixture(t)
	f.tenants(t, "cutover")
	f.seedIssued(t, "cutover", "operator-a", user.RoleAdmin, false)
	result := f.backfill(t, "cutover", 10)
	ctx := context.Background()
	prepared, err := f.store.PrepareCutover(ctx, "cutover", 0, "operator", time.Now().UTC())
	if err != nil || prepared.Phase != ports.IdentityCutoverShadow || prepared.PolicyVersion != 1 {
		t.Fatalf("prepare = %+v, %v", prepared, err)
	}
	canary, err := f.store.CanaryCutover(ctx, "cutover")
	if err != nil || canary.ID != result.Report.ID || !canary.Ready || !canary.RollbackPrepared {
		t.Fatalf("canary = %+v, %v", canary, err)
	}
	if err := f.store.RecordCutoverWriterHeartbeat(ctx, "cutover", "shared-authentication:test", "api-a", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.DeclareCutover(ctx, "cutover", prepared.PolicyVersion, ports.IdentityCutoverEvidence{ShadowReportID: canary.ID, OldWriterGeneration: "shared-authentication:test", MigrationVersion: identityMigrationCeiling(t)}, "operator", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AbortCutover(ctx, "cutover", 2, "operator", time.Now().UTC()); !errors.Is(err, ports.ErrIdentityCutover) {
		t.Fatalf("abort after declaration = %v", err)
	}
	var actions int
	if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM identity_cutover_ledger WHERE tenant_id=$1 AND action='declared'`, `cutover`).Scan(&actions); err != nil || actions != 1 {
		t.Fatalf("ledger = %d, %v", actions, err)
	}
}

func TestIdentityCutoverRejectsStaleEvidence(t *testing.T) {
	f := newIdentityFixture(t)
	f.tenants(t, "cutover-stale")
	f.seedIssued(t, "cutover-stale", "operator-a", user.RoleAdmin, false)
	result := f.backfill(t, "cutover-stale", 10)
	prepared, err := f.store.PrepareCutover(context.Background(), shared.ID("cutover-stale"), 0, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordCutoverWriterHeartbeat(context.Background(), "cutover-stale", "shared-authentication:test", "api-a", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.DeclareCutover(context.Background(), "cutover-stale", prepared.PolicyVersion, ports.IdentityCutoverEvidence{ShadowReportID: result.Report.ID, OldWriterGeneration: "shared-authentication:test", MigrationVersion: identityMigrationCeiling(t)}, "operator", time.Now().UTC().Add(25*time.Hour)); !errors.Is(err, ports.ErrIdentityCutover) {
		t.Fatalf("stale declaration = %v", err)
	}
}

func TestIdentityCutoverPrepareAbortPrepareAppendsAttempts(t *testing.T) {
	f := newIdentityFixture(t)
	f.tenants(t, "repeat")
	now := time.Now().UTC()
	first, err := f.store.PrepareCutover(context.Background(), "repeat", 0, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AbortCutover(context.Background(), "repeat", first.PolicyVersion, "operator", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.PrepareCutover(context.Background(), "repeat", first.PolicyVersion+1, "operator", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_cutover_ledger WHERE tenant_id='repeat' AND action='prepared'`); n != 2 {
		t.Fatalf("prepared attempts=%d", n)
	}
}

func identityMigrationCeiling(t *testing.T) int {
	t.Helper()
	versions, err := embeddedMigrationVersions()
	if err != nil {
		t.Fatal(err)
	}
	return int(versions[len(versions)-1])
}
