package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0093BackfillsComponentIdentityHash(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
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
	if err := goose.DownTo(db, ".", 92); err != nil {
		t.Fatalf("down to 0092: %v", err)
	}

	prefix := "m93-" + randHex(t)
	tenantID, engagementID, sbomID, componentID := prefix+"-tenant", prefix+"-engagement", prefix+"-sbom", prefix+"-component"
	purl := "pkg:golang/example.com/pkg@v1.2.3"
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagementID, tenantID); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO sboms(id,tenant_id,engagement_id,target_ref,source) VALUES($1,$2,$3,'test','test')`, sbomID, tenantID, engagementID); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO components(id,tenant_id,sbom_id,name,version,purl) VALUES($1,$2,$3,'pkg','v1.2.3',$4)`, componentID, tenantID, sbomID, purl); err != nil {
		t.Fatalf("seed component: %v", err)
	}
	if err := goose.UpTo(db, ".", 93); err != nil {
		t.Fatalf("up 0093: %v", err)
	}

	expected := sbom.ComponentFingerprint(sbom.ComponentIdentity{Ecosystem: "Go", Package: "example.com/pkg", Version: "v1.2.3"}, purl)
	var ecosystem, packageName, status, fingerprint string
	if err := db.QueryRowContext(ctx, `SELECT ecosystem,package_name,identity_status,identity_hash FROM components WHERE id=$1`, componentID).Scan(&ecosystem, &packageName, &status, &fingerprint); err != nil {
		t.Fatalf("read backfill: %v", err)
	}
	if ecosystem != "Go" || packageName != "example.com/pkg" || status != "resolved" || fingerprint != expected {
		t.Fatalf("backfill ecosystem=%q package=%q status=%q hash=%q, want hash=%q", ecosystem, packageName, status, fingerprint, expected)
	}
}
