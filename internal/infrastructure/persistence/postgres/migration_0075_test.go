package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func telEvent(comm string, at time.Time) detection.Event {
	return detection.Event{Class: detection.ClassProcess, At: at.UTC(), Host: "host-1",
		Process: &detection.ProcessEvent{PID: 1, Comm: comm, Path: "/usr/bin/" + comm}}
}

func TestMigration0075Telemetry(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenantA, tenantB := shared.ID("tel-a-"+id), shared.ID("tel-b-"+id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenantA.String(), tenantB.String()); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_events WHERE tenant_id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DROP OWNED BY tel_runtime`)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS tel_runtime`)
	})

	now := time.Now().UTC()
	repo := NewTelemetryRepository(pool, time.Hour, 2*time.Hour)
	tctx := shared.WithTenant(ctx, tenantA)

	// A full (seq 1) batch, then a sampled (seq 3) batch → a sequence gap AND a sampled window.
	if err := repo.Ingest(tctx, ports.TelemetryBatch{TenantID: tenantA, HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1",
		Class: detection.ClassProcess, Sequence: 1, SampleRate: 1, Events: []detection.Event{telEvent("ps", now.Add(-5*time.Minute)), telEvent("bash", now.Add(-5*time.Minute))}}); err != nil {
		t.Fatalf("ingest seq1: %v", err)
	}
	if err := repo.Ingest(tctx, ports.TelemetryBatch{TenantID: tenantA, HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1",
		Class: detection.ClassProcess, Sequence: 3, SampleRate: 10, Events: []detection.Event{telEvent("top", now.Add(-4*time.Minute))}}); err != nil {
		t.Fatalf("ingest seq3: %v", err)
	}
	if last, _ := repo.LastSequence(tctx, "host-1", detection.ClassProcess); last != 3 {
		t.Fatalf("last sequence = %d, want 3", last)
	}

	// Query the window: sampled + a sequence gap (seq 2 missing) → not complete.
	res, err := repo.Query(tctx, ports.HuntQuery{HostID: "host-1", Class: detection.ClassProcess})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("want 3 events, got %d", len(res.Events))
	}
	if !res.Sampled || res.MaxSampleRate != 10 {
		t.Errorf("sampled window must report its rate, got sampled=%v rate=%d", res.Sampled, res.MaxSampleRate)
	}
	if len(res.SequenceGaps) != 1 || res.SequenceGaps[0].Missing != 1 {
		t.Errorf("a missing sequence must surface as a gap, got %+v", res.SequenceGaps)
	}
	if res.Complete {
		t.Error("a sampled, gappy window must not report complete")
	}

	// RLS: a NOSUPERUSER role sees only its own tenant's rows.
	role := "tel_runtime"
	for _, q := range []string{
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='` + role + `') THEN EXECUTE 'DROP OWNED BY ` + role + `'; EXECUTE 'DROP ROLE ` + role + `'; END IF; END $$`,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON telemetry_events TO ` + role,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("prepare rls role: %v", err)
		}
	}
	countAs := func(tenant shared.ID) int {
		var n int
		tc := shared.WithTenant(context.Background(), tenant)
		if err := WithTenant(tc, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(tc, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(tc, `SELECT count(*) FROM telemetry_events`).Scan(&n)
		}); err != nil {
			t.Fatalf("count as %s: %v", tenant, err)
		}
		return n
	}
	if got := countAs(tenantB); got != 0 {
		t.Errorf("tenant B sees %d of tenant A's telemetry; RLS is not isolating", got)
	}
	if got := countAs(tenantA); got != 3 {
		t.Errorf("tenant A sees %d of its own telemetry, want 3", got)
	}

	// Footprint is observable. Rows is a planner estimate (pg_class.reltuples), which is 0 until stats are
	// gathered, so ANALYZE first to prove the estimate populates; Bytes is the real on-disk size.
	if _, err := pool.Exec(ctx, `ANALYZE telemetry_events`); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if fp, err := repo.Footprint(tctx); err != nil || fp.Rows < 1 || fp.Bytes <= 0 {
		t.Errorf("footprint must report rows(estimate)+bytes, got %+v err=%v", fp, err)
	}

	// Retention: an old event past the warm window is expired.
	if err := repo.Ingest(tctx, ports.TelemetryBatch{TenantID: tenantA, HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1",
		Class: detection.ClassNetwork, Sequence: 1, SampleRate: 1, Events: []detection.Event{{Class: detection.ClassNetwork, At: now.Add(-3 * time.Hour), Host: "host-1", Network: &detection.NetworkEvent{Proto: "udp", RemoteAddr: "8.8.8.8", RemotePort: 53, Direction: "egress"}}}}); err != nil {
		t.Fatalf("ingest old: %v", err)
	}
	rep, err := repo.RetentionSweep(tctx, now)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.Expired < 1 {
		t.Errorf("a past-warm event must be expired, got %+v", rep)
	}
}
