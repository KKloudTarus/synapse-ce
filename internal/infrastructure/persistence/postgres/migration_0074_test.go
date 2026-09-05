package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func mig74Detection(t *testing.T) detection.Detection {
	t.Helper()
	r, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration")
	}
	ev := detection.Event{Class: detection.ClassProcess, At: time.Unix(1, 0), Host: "host-x",
		Process: &detection.ProcessEvent{PID: 1, Comm: "ps", Path: "/usr/bin/ps"}}
	d, err := detection.NewDetection(r, "host-x", "agent:1", []detection.Event{ev}, time.Unix(500, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestMigration0074Detections(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenantA, tenantB := shared.ID("det-a-"+id), shared.ID("det-b-"+id)
	engA := "det-eng-" + id
	evID := "det-ev-" + id
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, []any{tenantA.String(), tenantB.String()}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'det-eng')`, []any{engA, tenantA.String()}},
		// A real evidence-chain link the detection references (FK evidence_id -> evidence(id)).
		{`INSERT INTO evidence(id,tenant_id,engagement_id,kind,sha256,previous_hash,storage_ref,content,created_by)
		   VALUES($1,$2,$3,'detection','deadbeef','','', $4,'agent:1')`, []any{evID, tenantA.String(), engA, []byte("{}")}},
	} {
		if _, err := pool.Exec(ctx, stmt.q, stmt.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, q := range []string{
			`DELETE FROM detections WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM evidence WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM engagements WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM tenants WHERE id IN ($1,$2)`,
		} {
			_, _ = pool.Exec(bg, q, tenantA.String(), tenantB.String())
		}
		_, _ = pool.Exec(bg, `DROP OWNED BY det_runtime`)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS det_runtime`)
	})

	repo := NewDetectionRecordRepository(pool)
	tctx := shared.WithTenant(ctx, tenantA)
	rec := detection.Record{
		ID: shared.ID("rec-" + id), TenantID: tenantA, EngagementID: shared.ID(engA), AssetID: "asset-x",
		AgentID: "agent:1", Detection: mig74Detection(t), EvidenceID: shared.ID(evID), BatchSeq: 1,
		RecordedAt: time.Unix(1000, 0).UTC(),
	}
	if err := repo.AppendDetection(tctx, rec); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Idempotent: a re-delivery of the same id does not duplicate.
	if err := repo.AppendDetection(tctx, rec); err != nil {
		t.Fatalf("re-append: %v", err)
	}
	if got, _ := repo.ListDetections(tctx, shared.ID(engA)); len(got) != 1 {
		t.Fatalf("append must be idempotent on id, got %d rows", len(got))
	}
	// HasDetection is engagement-scoped (tenant-scoped by ctx) and true for a stored id.
	if ok, err := repo.HasDetection(tctx, rec.EngagementID, rec.ID); err != nil || !ok {
		t.Fatalf("HasDetection must be true for a stored record (ok=%v err=%v)", ok, err)
	}
	// The same id under a DIFFERENT engagement must NOT match — a tenant-wide skip would silently drop
	// a distinct detection that happens to share the id (the D3 cross-engagement loss vector).
	if ok, err := repo.HasDetection(tctx, shared.ID("eng-other"), rec.ID); err != nil || ok {
		t.Fatalf("HasDetection must be engagement-scoped (ok=%v err=%v)", ok, err)
	}
	// A second, CRITICAL detection of the same rule+asset — so the incident rollup can be checked to
	// report the highest severity by RANK, not the alphabetical max of the label.
	crit := rec
	crit.ID = shared.ID("rec-crit-" + id)
	crit.EvidenceID = shared.ID(evID)
	crit.Detection.Severity = shared.SeverityCritical
	if err := repo.AppendDetection(tctx, crit); err != nil {
		t.Fatalf("append critical: %v", err)
	}

	// RLS under a NOSUPERUSER NOBYPASSRLS role (the pool superuser bypasses RLS).
	role := "det_runtime"
	for _, q := range []string{
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='` + role + `') THEN EXECUTE 'DROP OWNED BY ` + role + `'; EXECUTE 'DROP ROLE ` + role + `'; END IF; END $$`,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON detections, detection_incidents TO ` + role,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("prepare rls role: %v", err)
		}
	}
	countAs := func(tenant shared.ID, table string) int {
		var n int
		tc := shared.WithTenant(context.Background(), tenant)
		if err := WithTenant(tc, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(tc, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(tc, `SELECT count(*) FROM `+table).Scan(&n)
		}); err != nil {
			t.Fatalf("count as %s on %s: %v", tenant, table, err)
		}
		return n
	}
	if got := countAs(tenantB, "detections"); got != 0 {
		t.Errorf("tenant B sees %d of tenant A's detections; RLS is not isolating", got)
	}
	if got := countAs(tenantA, "detections"); got != 2 {
		t.Errorf("tenant A sees %d of its own detections, want 2; RLS is over-filtering", got)
	}
	// The incident rollup view is tenant-scoped too (security_invoker): B sees none, A sees its incident.
	if got := countAs(tenantB, "detection_incidents"); got != 0 {
		t.Errorf("tenant B sees %d incidents of tenant A; the rollup view leaks across tenants", got)
	}
	if got := countAs(tenantA, "detection_incidents"); got != 1 {
		t.Errorf("tenant A sees %d incidents, want 1 (one rule+asset)", got)
	}
	// worst_severity must be ranked, not lexical: an incident with low + critical reports 'critical'.
	var worst string
	tcA := shared.WithTenant(context.Background(), tenantA)
	if err := WithTenant(tcA, pool, tenantA.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(tcA, `SELECT worst_severity FROM detection_incidents LIMIT 1`).Scan(&worst)
	}); err != nil {
		t.Fatalf("read worst_severity: %v", err)
	}
	if worst != "critical" {
		t.Errorf("incident worst_severity = %q, want critical (ranked, not alphabetical max)", worst)
	}

	// Expiry is two-step: identify without mutation, then delete the exact projection.
	expRec := rec
	expRec.ID = shared.ID("rec-exp-" + id)
	expRec.ExpiresAt = time.Unix(2000, 0).UTC()
	if err := repo.AppendDetection(tctx, expRec); err != nil {
		t.Fatalf("append expiring: %v", err)
	}
	expired, err := repo.ListExpiredDetections(tctx, shared.ID(engA), time.Unix(3000, 0).UTC())
	if err != nil {
		t.Fatalf("list expired: %v", err)
	}
	if len(expired) != 1 || expired[0] != expRec.ID {
		t.Fatalf("only the past-retention record must be eligible, got %v", expired)
	}
	if ok, err := repo.HasDetection(tctx, expRec.EngagementID, expRec.ID); err != nil || !ok {
		t.Fatalf("listing expiry candidates must not delete the projection (ok=%v err=%v)", ok, err)
	}
	if deleted, err := repo.DeleteDetection(tctx, expRec.EngagementID, expRec.ID); err != nil || !deleted {
		t.Fatalf("delete expired projection: deleted=%v err=%v", deleted, err)
	}
	if deleted, err := repo.DeleteDetection(tctx, expRec.EngagementID, expRec.ID); err != nil || deleted {
		t.Fatalf("repeated delete must be idempotent: deleted=%v err=%v", deleted, err)
	}
	if got, _ := repo.ListDetections(tctx, shared.ID(engA)); len(got) != 2 {
		t.Fatalf("the two no-expiry records must remain after expiry, got %d", len(got))
	}
}

// TestDetectionRecordEngagementScopedKey proves the (tenant_id, engagement_id, id) uniqueness key
// (migration 0104): the SAME detection id delivered under two engagements of one tenant is TWO distinct
// rows, each bound to its own evidence link. Under the original (tenant_id, id) key the second engagement's
// row was silently dropped by ON CONFLICT DO NOTHING — the D3 cross-engagement loss vector.
func TestDetectionRecordEngagementScopedKey(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenant := shared.ID("detk-" + id)
	engA, engB := "detk-engA-"+id, "detk-engB-"+id
	evA, evB := "detk-evA-"+id, "detk-evB-"+id
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1)`, []any{tenant.String()}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$3,'detk-a'),($2,$3,'detk-b')`, []any{engA, engB, tenant.String()}},
		{`INSERT INTO evidence(id,tenant_id,engagement_id,kind,sha256,previous_hash,storage_ref,content,created_by)
		   VALUES($1,$3,$5,'detection','deadbeef','','', $7,'agent:1'),($2,$4,$6,'detection','feedface','','', $7,'agent:1')`,
			[]any{evA, evB, tenant.String(), tenant.String(), engA, engB, []byte("{}")}},
	} {
		if _, err := pool.Exec(ctx, stmt.q, stmt.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, q := range []string{
			`DELETE FROM detections WHERE tenant_id = $1`,
			`DELETE FROM evidence WHERE tenant_id = $1`,
			`DELETE FROM engagements WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = pool.Exec(bg, q, tenant.String())
		}
	})

	repo := NewDetectionRecordRepository(pool)
	tctx := shared.WithTenant(ctx, tenant)
	base := detection.Record{
		ID: shared.ID("dupe-" + id), TenantID: tenant, AssetID: "asset-x", AgentID: "agent:1",
		Detection: mig74Detection(t), BatchSeq: 1, RecordedAt: time.Unix(1000, 0).UTC(),
	}
	recA := base
	recA.EngagementID, recA.EvidenceID = shared.ID(engA), shared.ID(evA)
	recB := base
	recB.EngagementID, recB.EvidenceID = shared.ID(engB), shared.ID(evB)
	if err := repo.AppendDetection(tctx, recA); err != nil {
		t.Fatalf("append engA: %v", err)
	}
	if err := repo.AppendDetection(tctx, recB); err != nil {
		t.Fatalf("append engB (same id): %v", err)
	}
	// Idempotent within each engagement: a re-delivery is a no-op, not a duplicate.
	if err := repo.AppendDetection(tctx, recA); err != nil {
		t.Fatalf("re-append engA: %v", err)
	}

	if got, _ := repo.ListDetections(tctx, shared.ID(engA)); len(got) != 1 || got[0].EvidenceID != shared.ID(evA) {
		t.Fatalf("engA must retain its own row bound to %q, got %+v", evA, got)
	}
	if got, _ := repo.ListDetections(tctx, shared.ID(engB)); len(got) != 1 || got[0].EvidenceID != shared.ID(evB) {
		t.Fatalf("engB must retain its own row bound to %q, got %+v", evB, got)
	}
	if okA, _ := repo.HasDetection(tctx, shared.ID(engA), base.ID); !okA {
		t.Error("HasDetection(engA) must be true")
	}
	if okB, _ := repo.HasDetection(tctx, shared.ID(engB), base.ID); !okB {
		t.Error("HasDetection(engB) must be true")
	}
}
