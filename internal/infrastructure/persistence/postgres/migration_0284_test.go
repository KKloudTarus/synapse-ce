package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestMigration0284MarksImportsMadeAfter0280 (#1734): an engagement imported by a v0.3.0 binary after
// migration 0280 ran has its engagement.imported audit record but no import markers. The rerun marks its
// links, leaves native links alone, and adds nothing for an engagement 0280 already marked.
func TestMigration0284MarksImportsMadeAfter0280(t *testing.T) {
	const tenant, late, marked = "rerun-tenant", "rerun-late", "rerun-marked"
	pool, _ := ownershipMigrationDatabase(t, 282, 0, func(db *sql.DB) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenants(id,name) VALUES ($1,$1)`, []any{tenant}},
			{`SELECT set_config('app.current_tenant', $1, true)`, []any{tenant}},
			{`INSERT INTO engagements(id,tenant_id,name) VALUES ($1,$3,'late'),($2,$3,'marked')`, []any{late, marked, tenant}},
			// "late": imported after 0280 by an older binary, so two imported links and one native link, no markers.
			{`INSERT INTO evidence(id,tenant_id,engagement_id,kind,sha256,previous_hash,storage_ref,content,created_by,hash_scheme)
			   VALUES ('late-1',$1,$2,'scan','h1','','', 'a','op',1),('late-2',$1,$2,'scan','h2','h1','', 'b','op',1),('late-3',$1,$2,'scan','h3','h2','', 'c','op',1)`, []any{tenant, late}},
			{`INSERT INTO audit_log(tenant_id,actor,action,target,metadata,created_at,hash_version,hash_scheme)
			   VALUES ($1,'op','engagement.imported',$2,'{"evidence_links":"2"}',now(),2,1)`, []any{tenant, late}},
			// "marked": imported before 0280 and already marked by its backfill.
			{`INSERT INTO evidence(id,tenant_id,engagement_id,kind,sha256,previous_hash,storage_ref,content,created_by,hash_scheme)
			   VALUES ('marked-1',$1,$2,'scan','m1','','', 'd','op',1)`, []any{tenant, marked}},
			{`INSERT INTO audit_log(tenant_id,actor,action,target,metadata,created_at,hash_version,hash_scheme)
			   VALUES ($1,'op','engagement.imported',$2,'{"evidence_links":"1"}',now(),2,1)`, []any{tenant, marked}},
			{`INSERT INTO evidence_imports(tenant_id,engagement_id,evidence_id) VALUES ($1,$2,'marked-1')`, []any{tenant, marked}},
		} {
			if _, err := tx.Exec(q.sql, q.args...); err != nil {
				t.Fatalf("seed %q: %v", q.sql, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	})

	ctx := shared.WithTenant(context.Background(), tenant)
	store := NewEvidenceStore(pool)
	marks := func(eng string) map[string]bool {
		items, err := store.ListByEngagement(ctx, shared.ID(eng))
		if err != nil {
			t.Fatalf("list %s: %v", eng, err)
		}
		out := map[string]bool{}
		for _, it := range items {
			out[it.ID.String()] = it.Imported
		}
		return out
	}
	if got := marks(late); !got["late-1"] || !got["late-2"] || got["late-3"] {
		t.Fatalf("late marks = %v, want late-1 and late-2 only", got)
	}
	if got := marks(marked); !got["marked-1"] || len(got) != 1 {
		t.Fatalf("marked engagement = %v, want its one marker kept", got)
	}
}
