package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAttackPathImportedFindingBindings(t *testing.T) {
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
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	id := randHex(t)
	tenantA, tenantB := "attack-a-"+id, "attack-b-"+id
	engA, engA2, engB := "eng-a-"+id, "eng-a2-"+id, "eng-b-"+id
	assetA, canonicalA := "asset-a-"+id, "finding-a-"+id
	importedA, importedB := "imported-a-"+id, "imported-b-"+id
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1), ($2, $2)`, tenantA, tenantB); err != nil {
		t.Fatal(err)
	}
	// Bind the tenant this test acts as; the repositories refuse an unbound tenant so no query can
	// silently escape RLS. tenantB is exercised through its own explicit calls.
	ctx = shared.WithTenant(ctx, shared.ID(tenantA))
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	}()
	now := time.Now().UTC()
	for _, in := range []struct{ id, tenant string }{{engA, tenantA}, {engA2, tenantA}, {engB, tenantB}} {
		eng, _ := engagement.New(shared.ID(in.id), shared.ID(in.tenant), in.id, "client", now)
		if err := NewEngagementRepository(pool).Create(ctx, eng); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := asset.New(shared.ID(assetA), shared.ID(tenantA), asset.KindImage, "sha256:"+id, "image", nil, now)
	if err := NewAssetRepository(pool).UpsertAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	canonical := finding.Finding{ID: shared.ID(canonicalA), EngagementID: shared.ID(engA), Title: "canonical", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: "canonical:" + id, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	if err := NewFindingRepository(pool).Upsert(ctx, []finding.Finding{canonical}); err != nil {
		t.Fatal(err)
	}
	imports := NewImportedFindingRepository(pool)
	makeImported := func(id, tenant, engagement string) importedfinding.ImportedFinding {
		return importedfinding.ImportedFinding{ID: shared.ID(id), TenantID: shared.ID(tenant), EngagementID: shared.ID(engagement), Severity: shared.SeverityHigh, Title: "imported", Message: "external", Location: importedfinding.Location{Path: "src/a.go", StartLine: 1}, Provenance: importedfinding.Provenance{ToolName: "tool", ToolVersion: "1", RuleID: "rule." + id, SourceDigest: "digest." + id, IngestedBy: "human:test", IngestedAt: now}, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	}
	if _, _, err := imports.Save(ctx, shared.ID(tenantA), []importedfinding.ImportedFinding{makeImported(importedA, tenantA, engA)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := imports.Save(ctx, shared.ID(tenantB), []importedfinding.ImportedFinding{makeImported(importedB, tenantB, engB)}); err != nil {
		t.Fatal(err)
	}

	store := NewAttackPathStore(pool)
	canonicalBinding := attackpath.Binding{TenantID: shared.ID(tenantA), EngagementID: shared.ID(engA), AssetID: shared.ID(assetA), FindingID: shared.ID(canonicalA), TargetKind: attackpath.TargetCanonical, Producer: "canonical", Provenance: "canonical", Confidence: asset.EdgeObserved}
	importedBinding := attackpath.Binding{TenantID: shared.ID(tenantA), EngagementID: shared.ID(engA), AssetID: shared.ID(assetA), FindingID: shared.ID(importedA), TargetKind: attackpath.TargetImported, Producer: "imported", Provenance: "imported", Confidence: asset.EdgeObserved}
	if err := store.ReplaceBindings(ctx, shared.ID(tenantA), shared.ID(engA), "imported", []attackpath.Binding{importedBinding}); err != nil {
		t.Fatalf("store imported binding: %v", err)
	}
	got, err := store.ListBindings(ctx, shared.ID(tenantA))
	if err != nil || len(got) != 1 || got[0] != importedBinding {
		t.Fatalf("imported-only binding = %#v, %v", got, err)
	}
	if err := store.ReplaceBindings(ctx, shared.ID(tenantA), shared.ID(engA), "canonical", []attackpath.Binding{canonicalBinding}); err != nil {
		t.Fatalf("store canonical binding: %v", err)
	}
	got, err = store.ListBindings(ctx, shared.ID(tenantA))
	if err != nil || len(got) != 2 || got[0] != canonicalBinding || got[1] != importedBinding {
		t.Fatalf("binding round trip = %#v, %v", got, err)
	}

	insert := func(toID, kind, canonicalID, importedID string, tenant, engagement string) error {
		return WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO attack_path_edges
				(tenant_id, engagement_id, from_kind, from_id, to_kind, to_id, target_kind, canonical_finding_id, imported_finding_id, kind, producer, provenance, confidence)
				VALUES ($1,$2,'asset',$3,'finding',$4,$5,NULLIF($6,''),NULLIF($7,''),'affected_by','reject','reject',$8)`,
				tenant, engagement, assetA, toID, kind, canonicalID, importedID, string(asset.EdgeObserved))
			return err
		})
	}
	if err := insert("missing-"+id, "imported", "", "missing-"+id, tenantA, engA); err == nil {
		t.Fatal("dangling imported target must fail")
	}
	if err := insert(importedB, "imported", "", importedB, tenantA, engA); err == nil {
		t.Fatal("cross-tenant imported target must fail")
	}
	if err := insert(importedA, "imported", "", importedA, tenantA, engA2); err == nil {
		t.Fatal("cross-engagement imported target must fail")
	}

	role := uniqueProbeRole(t, dsn, "attack_path_0070_role")
	_, _ = pool.Exec(ctx, `DROP OWNED BY `+role)
	_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	for _, stmt := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON attack_path_edges TO ` + role,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("set up no-tenant RLS role: %v", err)
		}
	}
	if err := WithTenant(ctx, pool, "", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
			return err
		}
		var visible int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM attack_path_edges WHERE tenant_id=$1`, tenantA).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			t.Fatalf("no-tenant RLS query saw %d attack path bindings", visible)
		}
		return nil
	}); err != nil {
		t.Fatalf("no-tenant RLS query: %v", err)
	}
}
