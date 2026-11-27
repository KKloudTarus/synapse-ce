package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestMigration0280MarksImportedEvidence: the backfill marks the links an engagement.imported record
// counted, and only those; the store marks links appended as imported and reads the mark back.
func TestMigration0280MarksImportedEvidence(t *testing.T) {
	const tenant, imported, native = "imp-tenant", "imp-eng", "native-eng"
	pool, _ := ownershipMigrationDatabase(t, 278, 0, func(db *sql.DB) {
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
			{`INSERT INTO engagements(id,tenant_id,name) VALUES ($1,$3,'imported'),($2,$3,'native')`, []any{imported, native, tenant}},
			// Two links arrived with the bundle, a third was sealed here afterwards.
			{`INSERT INTO evidence(id,tenant_id,engagement_id,kind,sha256,previous_hash,storage_ref,content,created_by)
			   VALUES ('imp-1',$1,$2,'scan','h1','','', 'a','op'),('imp-2',$1,$2,'scan','h2','h1','', 'b','op'),('imp-3',$1,$2,'scan','h3','h2','', 'c','op'),
			          ('nat-1',$1,$3,'scan','n1','','', 'd','op')`, []any{tenant, imported, native}},
			{`INSERT INTO audit_log(tenant_id,actor,action,target,metadata,created_at,hash_version)
			   VALUES ($1,'op','engagement.imported',$2,'{"evidence_links":"2"}',now(),2)`, []any{tenant, imported}},
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
	if got := marks(imported); !got["imp-1"] || !got["imp-2"] || got["imp-3"] {
		t.Fatalf("backfill marks = %v, want imp-1 and imp-2 only", got)
	}
	if got := marks(native); got["nat-1"] {
		t.Fatalf("a native link was marked imported: %v", got)
	}

	link := evidence.Evidence{ID: "imp-4", EngagementID: imported, Kind: "scan", Content: []byte("e"), PreviousHash: "h3", CreatedBy: "op", CreatedAt: time.Now().UTC(), Imported: true}.Seal()
	if err := store.Append(ctx, []evidence.Evidence{link}); err != nil {
		t.Fatalf("append imported link: %v", err)
	}
	if got := marks(imported); !got["imp-4"] {
		t.Fatalf("an appended imported link reads back unmarked: %v", got)
	}
}
