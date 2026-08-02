package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestTenantRLSIsolation exercises actual PostgreSQL policies. It is opt-in so
// ordinary unit tests do not need a database. Supply a non-superuser runtime
// DSN and a separate migration/admin DSN.
func TestTenantRLSIsolation(t *testing.T) {
	runtimeDSN := os.Getenv("SYNAPSE_TEST_POSTGRES_DSN")
	adminDSN := os.Getenv("SYNAPSE_TEST_POSTGRES_MIGRATE_DSN")
	if runtimeDSN == "" || adminDSN == "" {
		t.Skip("set SYNAPSE_TEST_POSTGRES_DSN and SYNAPSE_TEST_POSTGRES_MIGRATE_DSN to run PostgreSQL RLS integration")
	}
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	admin, err := Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close()
	runtime, err := Connect(ctx, runtimeDSN)
	if err != nil {
		t.Fatalf("connect runtime: %v", err)
	}
	defer runtime.Close()
	if err := RequireNonSuperuser(ctx, runtime); err != nil {
		t.Fatalf("runtime role: %v", err)
	}

	suffix := fmt.Sprintf("rls-%d", time.Now().UnixNano())
	tenantA, tenantB, projectID, engagementID := suffix+"-a", suffix+"-b", suffix+"-project", suffix+"-engagement"
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := admin.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, tenant, tenant); err != nil {
			t.Fatalf("insert tenant %q: %v", tenant, err)
		}
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, `DELETE FROM projects WHERE id=$1`, projectID)
		_, _ = admin.Exec(ctx, `DELETE FROM engagements WHERE id=$1`, engagementID)
		_, _ = admin.Exec(ctx, `DELETE FROM tenants WHERE id = ANY($1)`, []string{tenantA, tenantB})
	})

	if err := WithTenantTx(ctx, runtime, shared.ID(tenantA), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding, default_profile_by_lang, gate_id, created_at, updated_at, created_by, updated_by) VALUES ($1,$2,'RLS test',$3,'{}','{}','',now(),now(),'test','test')`, projectID, tenantA, suffix)
		return err
	}); err != nil {
		t.Fatalf("insert tenant A project: %v", err)
	}

	var count int
	if err := runtime.QueryRow(ctx, `SELECT count(*) FROM projects WHERE id=$1`, projectID).Scan(&count); err != nil {
		t.Fatalf("query without tenant context: %v", err)
	}
	if count != 0 {
		t.Fatalf("unset tenant context exposed %d rows", count)
	}
	if err := WithTenantTx(ctx, runtime, shared.ID(tenantB), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM projects WHERE id=$1`, projectID).Scan(&count)
	}); err != nil {
		t.Fatalf("query tenant B: %v", err)
	}
	if count != 0 {
		t.Fatalf("tenant B exposed %d tenant A rows", count)
	}
	if err := WithTenantTx(ctx, runtime, shared.ID(tenantA), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM projects WHERE id=$1`, projectID).Scan(&count)
	}); err != nil {
		t.Fatalf("query tenant A: %v", err)
	}
	if count != 1 {
		t.Fatalf("tenant A count = %d, want 1", count)
	}

	eng, err := engagement.New(shared.ID(engagementID), shared.ID(tenantA), "RLS engagement", "", time.Now().UTC())
	if err != nil {
		t.Fatalf("new engagement: %v", err)
	}
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "example.test"}}}
	if err := NewEngagementRepository(runtime).Create(ctx, eng); err != nil {
		t.Fatalf("create tenant A engagement: %v", err)
	}
	if err := WithTenantTx(ctx, runtime, shared.ID(tenantB), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM engagements WHERE id=$1`, engagementID).Scan(&count)
	}); err != nil {
		t.Fatalf("query tenant B engagement: %v", err)
	}
	if count != 0 {
		t.Fatalf("tenant B exposed %d tenant A engagements", count)
	}
	if err := WithTenantTx(ctx, runtime, shared.ID(tenantB), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM scope_targets WHERE engagement_id=$1`, engagementID).Scan(&count)
	}); err != nil {
		t.Fatalf("query tenant B scope: %v", err)
	}
	if count != 0 {
		t.Fatalf("tenant B exposed %d tenant A scope targets", count)
	}

	ctxA := shared.WithTenant(ctx, shared.ID(tenantA))
	findingID := suffix + "-finding"
	if err := NewFindingRepository(runtime).Upsert(ctxA, []finding.Finding{{ID: shared.ID(findingID), EngagementID: shared.ID(engagementID), Title: "RLS finding", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: suffix + "-dedup"}}); err != nil {
		t.Fatalf("create tenant A finding: %v", err)
	}
	if err := NewEvidenceStore(runtime).Append(ctxA, []evidence.Evidence{{ID: shared.ID(suffix + "-evidence"), EngagementID: shared.ID(engagementID), FindingID: shared.ID(findingID), Kind: "scan", Content: []byte("rls evidence"), Hash: suffix + "-hash", CreatedAt: time.Now().UTC()}}); err != nil {
		t.Fatalf("create tenant A evidence: %v", err)
	}
	for _, table := range []string{"findings", "evidence"} {
		if err := WithTenantTx(ctx, runtime, shared.ID(tenantB), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE engagement_id=$1`, engagementID).Scan(&count)
		}); err != nil {
			t.Fatalf("query tenant B %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("tenant B exposed %d tenant A %s rows", count, table)
		}
	}

	sessionID := shared.ID(suffix + "-session")
	if err := NewAgentSessionStore(runtime).SaveSession(ctxA, agent.Session{ID: sessionID, EngagementID: shared.ID(engagementID), InitiatedBy: "operator", Goal: "RLS session", Status: agent.StatusRunning, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create tenant A agent session: %v", err)
	}
	if err := NewAgentSessionStore(runtime).AppendMessage(ctxA, sessionID, 0, agent.Message{Role: agent.RoleUser, Content: "RLS message"}); err != nil {
		t.Fatalf("create tenant A agent message: %v", err)
	}
	for _, table := range []string{"agent_sessions", "agent_messages"} {
		if err := WithTenantTx(ctx, runtime, shared.ID(tenantB), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1`, tenantA).Scan(&count)
		}); err != nil {
			t.Fatalf("query tenant B %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("tenant B exposed %d tenant A %s rows", count, table)
		}
	}

	if err := NewReconRunStore(runtime).Save(ctxA, recon.Run{ID: shared.ID(suffix + "-recon"), EngagementID: shared.ID(engagementID), Tool: "subfinder", Target: "example.test", Status: recon.StatusRunning, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create tenant A recon run: %v", err)
	}
	if err := NewScanJobStore(runtime).CreateRunning(ctxA, ports.ScanJob{ID: suffix + "-scan", EngagementID: engagementID, Target: "example.test", Kind: "local", Status: ports.ScanRunning, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create tenant A scan job: %v", err)
	}
	for _, table := range []string{"recon_runs", "scan_jobs"} {
		if err := WithTenantTx(ctx, runtime, shared.ID(tenantB), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1`, tenantA).Scan(&count)
		}); err != nil {
			t.Fatalf("query tenant B %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("tenant B exposed %d tenant A %s rows", count, table)
		}
	}
}
