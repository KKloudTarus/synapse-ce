package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type cutoverRestoreSnapshot struct {
	users, memberships, ledger, audit int
	phase                             string
	policyVersion                     int
}

// TestIdentityCutoverSnapshotRestoreAndForwardFixDrill models the operator's paired-backup drill
// without ever restoring the configured test base. CREATE DATABASE ... TEMPLATE is PostgreSQL's
// consistent physical snapshot: the source pools must be closed before it can be used as a template.
func TestIdentityCutoverSnapshotRestoreAndForwardFixDrill(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	tenant := shared.ID("cutover-restore")
	f.tenants(t, tenant.String())
	digest := f.seedIssued(t, tenant.String(), "restore-admin", user.RoleAdmin, false)
	backfill := f.backfill(t, tenant.String(), 10)
	prepared, err := f.store.PrepareCutover(ctx, tenant, 0, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	canary, err := f.store.CanaryCutover(ctx, tenant)
	if err != nil || !canary.Ready || !canary.RollbackPrepared || canary.ID != backfill.Report.ID {
		t.Fatalf("pre-snapshot canary=%+v err=%v", canary, err)
	}
	before := readCutoverRestoreSnapshot(t, f.admin, tenant)

	// Use an independent control connection. No DSN is reported: the fixture's generated database
	// and roles remain private to this test process.
	controlDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if controlDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the identity cutover restore drill")
	}
	adminDSN, runtimeDSN, ownerDSN := f.admin.Config().ConnString(), f.runtime.Config().ConnString(), f.owner.Config().ConnString()
	sourceDB := f.admin.Config().ConnConfig.Database
	cloneDB := "identity_restore_" + identityRandomHex(t, 6)
	quote := func(v string) string { return pgx.Identifier{v}.Sanitize() }

	// PostgreSQL refuses a template with active sessions. Reopen the same fixture configurations
	// immediately afterwards so declaration and the forward-only repair run on the original database.
	f.runtime.Close()
	f.owner.Close()
	f.admin.Close()
	control, err := pgx.Connect(ctx, controlDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Exec(ctx, `CREATE DATABASE `+quote(cloneDB)+` TEMPLATE `+quote(sourceDB)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := control.Exec(cleanup, `DROP DATABASE `+quote(cloneDB)+` WITH (FORCE)`); err != nil {
			t.Error(err)
		}
		_ = control.Close(cleanup)
	})
	f.admin, err = pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime, err = pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = pgxpool.New(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	f.store, err = NewIdentityFoundationStore(f.runtime)
	if err != nil {
		t.Fatal(err)
	}

	cloneAdminDSN := cutoverRestoreDatabaseDSN(t, controlDSN, cloneDB)
	cloneRuntimeDSN := cutoverRestoreDatabaseDSN(t, runtimeDSN, cloneDB)
	cloneAdmin, err := pgxpool.New(ctx, cloneAdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer cloneAdmin.Close()
	cloneRuntime, err := pgxpool.New(ctx, cloneRuntimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer cloneRuntime.Close()
	cloneStore, err := NewIdentityFoundationStore(cloneRuntime)
	if err != nil {
		t.Fatal(err)
	}

	// Declaration is terminal. Contract is the supported forward-only completion step and must
	// append evidence without deleting the declaration or prior audit chain.
	declareAt := time.Now().UTC()
	if err = f.store.RecordCutoverWriterHeartbeat(ctx, tenant, "shared-authentication:fixture", "api-a", declareAt); err != nil {
		t.Fatal(err)
	}
	declared, err := f.store.DeclareCutover(ctx, tenant, prepared.PolicyVersion, ports.IdentityCutoverEvidence{ShadowReportID: canary.ID, OldWriterGeneration: "shared-authentication:fixture", MigrationVersion: identityMigrationCeiling(t)}, "operator", declareAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AbortCutover(ctx, tenant, declared.PolicyVersion, "operator", declareAt.Add(time.Second)); !errors.Is(err, ports.ErrIdentityCutover) {
		t.Fatalf("terminal declaration allowed rollback: %v", err)
	}
	if _, err = f.store.ContractCutover(ctx, tenant, declared.PolicyVersion, "operator", declareAt.Add(2*time.Second)); err != nil {
		t.Fatalf("forward-only contract: %v", err)
	}
	after := readCutoverRestoreSnapshot(t, f.admin, tenant)
	if after.ledger <= before.ledger || after.audit < before.audit {
		t.Fatalf("forward fix did not preserve append-only evidence before=%+v after=%+v", before, after)
	}

	// The isolated clone is the pre-declaration restore target. It must retain both legacy access
	// and native projections, their exact credential routing, and the policy/ledger snapshot.
	restored := readCutoverRestoreSnapshot(t, cloneAdmin, tenant)
	if restored != before {
		t.Fatalf("restored snapshot drift got=%+v want=%+v", restored, before)
	}
	if n := cutoverRestoreCount(t, cloneRuntime, tenant, `SELECT count(*) FROM users WHERE tenant_id=$1 AND id='restore-admin'`, tenant.String()); n != 1 {
		t.Fatalf("restored legacy user count=%d", n)
	}
	if n := cutoverRestoreCount(t, cloneRuntime, tenant, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, tenant.String()); n != 1 {
		t.Fatalf("restored membership count=%d", n)
	}
	route, err := cloneStore.RouteCredentialDigest(ctx, digest)
	if err != nil || route.TenantID != tenant || route.Kind != ports.IdentityCredentialAPIKey {
		t.Fatalf("restored credential route=%+v err=%v", route, err)
	}
}

func cutoverRestoreDatabaseDSN(t *testing.T, raw, database string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path, u.RawPath = "/"+database, ""
	return u.String()
}

func readCutoverRestoreSnapshot(t *testing.T, pool *pgxpool.Pool, tenant shared.ID) cutoverRestoreSnapshot {
	t.Helper()
	var out cutoverRestoreSnapshot
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM users WHERE tenant_id=$1),
		(SELECT count(*) FROM identity_memberships WHERE tenant_id=$1),
		(SELECT count(*) FROM identity_cutover_ledger WHERE tenant_id=$1),
		(SELECT count(*) FROM audit_log WHERE tenant_id=$1),
		(SELECT cutover_phase FROM identity_policies WHERE tenant_id=$1),
		(SELECT version FROM identity_policies WHERE tenant_id=$1)`, tenant.String()).Scan(&out.users, &out.memberships, &out.ledger, &out.audit, &out.phase, &out.policyVersion); err != nil {
		t.Fatal(err)
	}
	return out
}

func cutoverRestoreCount(t *testing.T, pool *pgxpool.Pool, tenant shared.ID, query string, args ...any) int {
	t.Helper()
	var count int
	if err := WithTenant(context.Background(), pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), query, args...).Scan(&count)
	}); err != nil {
		t.Fatal(err)
	}
	return count
}
