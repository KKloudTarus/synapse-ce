package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAttackPathStoreRejectsMismatchedBatchAtomically(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// t.Cleanup, not defer: a deferred Close runs when this function RETURNS, which is before any
	// t.Cleanup callback -- so the cleanups below were dropping objects through an already-closed pool
	// and, because their errors were discarded, failed in silence. LIFO ordering runs the drops first.
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenant, engagementID, assetID, findingID := shared.ID("attack-"+id), shared.ID("eng-"+id), shared.ID("asset-"+id), shared.ID("finding-"+id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.String()) })
	// The repositories run every statement through WithTenant, which refuses an unbound tenant so no
	// query can silently escape RLS. This helper therefore needs a tenant-bound context for its
	// repository calls, the same as httpapi/auth.go and the worker provide for real callers. The raw
	// pool.Exec calls above stay on a plain context: they seed the tenants row itself, before there is
	// a tenant to act as.
	ctx = shared.WithTenant(ctx, tenant)
	now := time.Now().UTC()
	eng, _ := engagement.New(engagementID, tenant, "eng", "client", now)
	if err := NewEngagementRepository(pool).Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	a, _ := asset.New(assetID, tenant, asset.KindImage, "sha256:"+id, "image", nil, now)
	if err := NewAssetRepository(pool).UpsertAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	f := finding.Finding{ID: findingID, EngagementID: engagementID, Title: "finding", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: "vuln:" + id, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	if err := NewFindingRepository(pool).Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatal(err)
	}
	store := NewAttackPathStore(pool)
	valid := attackpath.Binding{TenantID: tenant, EngagementID: engagementID, AssetID: assetID, FindingID: findingID, TargetKind: attackpath.TargetCanonical, Producer: "producer", Provenance: "provenance", Confidence: asset.EdgeObserved}
	if err := store.ReplaceBindings(ctx, tenant, engagementID, valid.Producer, []attackpath.Binding{valid}); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]attackpath.Binding{
		"producer":   func() attackpath.Binding { b := valid; b.Producer = "other"; return b }(),
		"tenant":     func() attackpath.Binding { b := valid; b.TenantID = "other"; return b }(),
		"engagement": func() attackpath.Binding { b := valid; b.EngagementID = "other"; return b }(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.ReplaceBindings(ctx, tenant, engagementID, valid.Producer, []attackpath.Binding{invalid}); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("ReplaceBindings() error = %v, want validation", err)
			}
			got, err := store.ListBindings(ctx, tenant)
			if err != nil || len(got) != 1 || got[0] != valid {
				t.Fatalf("bindings after rejected replace = %#v, %v", got, err)
			}
		})
	}
}

func TestAttackPathStoreReplaceBindingsSerializesProducer(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenant, engagementID := shared.ID("attack-"+id), shared.ID("eng-"+id)
	assets := []shared.ID{"asset-a-" + shared.ID(id), "asset-b-" + shared.ID(id), "asset-c-" + shared.ID(id), "asset-d-" + shared.ID(id)}
	findings := []shared.ID{"finding-a-" + shared.ID(id), "finding-b-" + shared.ID(id), "finding-c-" + shared.ID(id), "finding-d-" + shared.ID(id)}
	seedAttackPathTargets(t, pool, tenant, engagementID, assets, findings, id, false)

	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_lock(9419001)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = blocker.Exec(context.Background(), `SELECT pg_advisory_unlock(9419001)`) }()
	if _, err := pool.Exec(ctx, `CREATE OR REPLACE FUNCTION attack_path_pause_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(9419001); RETURN OLD; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER attack_path_pause_delete BEFORE DELETE ON attack_path_edges FOR EACH STATEMENT EXECUTE FUNCTION attack_path_pause_delete()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, statement := range []string{
			`DROP TRIGGER IF EXISTS attack_path_pause_delete ON attack_path_edges`,
			`DROP FUNCTION IF EXISTS attack_path_pause_delete()`,
		} {
			if _, err := pool.Exec(context.Background(), statement); err != nil {
				t.Errorf("cleanup %q: %v (the next run of this test will fail)", statement, err)
			}
		}
	})

	bindings := func(offset int) []attackpath.Binding {
		return []attackpath.Binding{
			{TenantID: tenant, EngagementID: engagementID, AssetID: assets[offset], FindingID: findings[offset], TargetKind: attackpath.TargetCanonical, Producer: "producer", Provenance: "a", Confidence: asset.EdgeObserved},
			{TenantID: tenant, EngagementID: engagementID, AssetID: assets[offset+1], FindingID: findings[offset+1], TargetKind: attackpath.TargetCanonical, Producer: "producer", Provenance: "b", Confidence: asset.EdgeObserved},
		}
	}
	waitForAdvisoryLock := func(query string) {
		waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var waiting bool
			err := pool.QueryRow(waitCtx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE query=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, query).Scan(&waiting)
			if err != nil {
				t.Fatalf("query activity: %v", err)
			}
			if waiting {
				return
			}
			select {
			case <-waitCtx.Done():
				t.Fatalf("wait for advisory lock on %q: %v", query, waitCtx.Err())
			case <-ticker.C:
			}
		}
	}

	store := NewAttackPathStore(pool)
	firstDone := make(chan error, 1)
	go func() { firstDone <- store.ReplaceBindings(ctx, tenant, engagementID, "producer", bindings(0)) }()
	waitForAdvisoryLock(`DELETE FROM attack_path_edges WHERE tenant_id=$1 AND engagement_id=$2 AND producer=$3`)
	secondDone := make(chan error, 1)
	go func() { secondDone <- store.ReplaceBindings(ctx, tenant, engagementID, "producer", bindings(2)) }()
	waitForAdvisoryLock(`SELECT pg_advisory_xact_lock($1)`)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_unlock(9419001)`); err != nil {
		t.Fatal(err)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("first replacement: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second replacement: %v", err)
	}
	got, err := store.ListBindings(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	want := bindings(2)
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("serialized replacement = %#v, want %#v", got, want)
	}
}

func TestMigration0069DownDeduplicatesProducers(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := MigrateLocked(context.Background(), dsn); err != nil {
			t.Errorf("restore migrations: %v", err)
		}
	})
	db := openLockedGooseDB(t, dsn)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 69); err != nil {
		t.Fatalf("down to 68: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	id := randHex(t)
	tenant, engagementID := shared.ID("rollback-"+id), shared.ID("eng-"+id)
	assetID, findingID := shared.ID("asset-"+id), shared.ID("finding-"+id)
	seedAttackPathTargets(t, pool, tenant, engagementID, []shared.ID{assetID}, []shared.ID{findingID}, id, true)
	for _, producer := range []string{"zeta", "alpha"} {
		if _, err := pool.Exec(ctx, `INSERT INTO attack_path_edges (tenant_id, engagement_id, from_kind, from_id, to_kind, to_id, kind, producer, provenance, confidence) VALUES ($1,$2,'asset',$3,'finding',$4,'affected_by',$5,'same',$6)`, tenant.String(), engagementID.String(), assetID.String(), findingID.String(), producer, string(asset.EdgeObserved)); err != nil {
			t.Fatal(err)
		}
	}
	if err := goose.DownTo(db, ".", 68); err != nil {
		t.Fatalf("down to 67: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM attack_path_edges WHERE tenant_id=$1 AND provenance='same'`, tenant.String()).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rollback retained %d legacy rows, want 1", count)
	}
	if err := goose.UpTo(db, ".", 71); err != nil {
		t.Fatalf("restore migrations: %v", err)
	}
}

func seedAttackPathTargets(t *testing.T, pool *pgxpool.Pool, tenant, engagementID shared.ID, assets, findings []shared.ID, suffix string, legacyFindingSchema bool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO tenants (id, name) VALUES ($1, $1)`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.String()) })
	// Repositories run every statement through WithTenant, which refuses an unbound tenant so no query
	// can silently escape RLS. Bind the tenant this test acts as -- after its row exists -- exactly as
	// httpapi/auth.go and the worker do.
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC()
	eng, _ := engagement.New(engagementID, tenant, "eng", "client", now)
	if err := NewEngagementRepository(pool).Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	for i := range assets {
		a, _ := asset.New(assets[i], tenant, asset.KindImage, fmt.Sprintf("sha256:%s-%d", suffix, i), "image", nil, now)
		if err := NewAssetRepository(pool).UpsertAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
		if legacyFindingSchema {
			if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO findings (id, tenant_id, engagement_id, title, severity, status, dedup_key, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, findings[i].String(), tenant.String(), engagementID.String(), "finding", string(shared.SeverityHigh), string(finding.StatusOpen), fmt.Sprintf("vuln:%s:%d", suffix, i), now, now)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		f := finding.Finding{ID: findings[i], EngagementID: engagementID, Title: "finding", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: fmt.Sprintf("vuln:%s:%d", suffix, i), Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
		if err := NewFindingRepository(pool).Upsert(ctx, []finding.Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
}
