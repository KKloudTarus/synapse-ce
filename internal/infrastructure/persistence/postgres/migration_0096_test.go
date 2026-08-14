package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0096CPEPersistenceAndLookup(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if err := Migrate(context.Background(), dsn); err != nil {
			t.Errorf("restore migrations: %v", err)
		}
	})
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 95); err != nil {
		t.Fatalf("down to 0095: %v", err)
	}
	if err := goose.UpTo(db, ".", 96); err != nil {
		t.Fatalf("up 0096: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	for _, object := range []string{"idx_components_cpe_lookup", "advisory_cpe_affects"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, object).Scan(&exists); err != nil || !exists {
			t.Fatalf("object %s exists=%v err=%v", object, exists, err)
		}
	}

	prefix := "m96-" + randHex(t)
	tenantID := shared.ID(prefix + "-tenant")
	engagementID := shared.ID(prefix + "-engagement")
	sbomID := shared.ID(prefix + "-sbom")
	componentID := shared.ID(prefix + "-component")
	advisoryID := prefix + "-advisory"
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1)`, []any{tenantID.String()}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'CPE')`, []any{engagementID.String(), tenantID.String()}},
		{`INSERT INTO sboms(id,tenant_id,engagement_id,target_ref,source,created_at) VALUES($1,$2,$3,'image','test',$4)`, []any{sbomID.String(), tenantID.String(), engagementID.String(), now}},
		{`INSERT INTO components(id,tenant_id,sbom_id,name,version,cpe,cpe_part,cpe_vendor,cpe_product,cpe_hash,cpe_status) VALUES($1,$2,$3,'widget','1.0.0','cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*','a','acme','widget','cpe-hash','resolved')`, []any{componentID.String(), tenantID.String(), sbomID.String()}},
		{`INSERT INTO advisories(id,data) VALUES($1,$2)`, []any{advisoryID, []byte(`{"id":"` + advisoryID + `"}`)}},
		{`INSERT INTO advisory_cpe_affects(advisory_id,cpe_part,cpe_vendor,cpe_product) VALUES($1,'a','acme','widget')`, []any{advisoryID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed 0096 fixture: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM advisories WHERE id=$1`, advisoryID)
		_, _ = pool.Exec(bg, `DELETE FROM sboms WHERE id=$1`, sbomID.String())
		_, _ = pool.Exec(bg, `DELETE FROM engagements WHERE id=$1`, engagementID.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenantID.String())
	})

	tenantCtx := shared.WithTenant(ctx, tenantID)
	page, err := NewComponentInventoryStore(pool).ListCurrentComponents(tenantCtx, sbom.ComponentQuery{
		TenantID: tenantID, EngagementID: engagementID, CPEPart: "A", CPEVendor: "ACME", CPEProduct: "Widget", Limit: 10,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("CPE component page=%+v err=%v", page, err)
	}
	item := page.Items[0]
	if item.CPEStatus != sbom.IdentityResolved || item.CPEPart != "a" || item.CPEVendor != "acme" || item.CPEProduct != "widget" || item.CPEHash != "cpe-hash" {
		t.Fatalf("persisted CPE=%+v", item)
	}
	advisories, err := NewAdvisoryMaterializer(pool).ByCPE(ctx, "A", "ACME", "Widget")
	if err != nil || len(advisories) != 1 || advisories[0].ID != advisoryID {
		t.Fatalf("CPE advisory lookup=%+v err=%v", advisories, err)
	}
}
