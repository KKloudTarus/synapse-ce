package postgres

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestMigration0283ImportedLinksKeepTheirSealedFinding (#1722): an imported finding-linked link stores the
// finding id it was sealed with on its import marker, both chain readers return it, the chain verifies
// with the remapped finding id in place, and the marker row is append-only.
func TestMigration0283ImportedLinksKeepTheirSealedFinding(t *testing.T) {
	const tenant, eng = "sealed-tenant", "sealed-eng"
	pool, owner := ownershipMigrationDatabase(t, 282, 0, func(db *sql.DB) {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenants(id,name) VALUES ($1,$1)`, []any{tenant}},
			{`WITH bound AS (SELECT set_config('app.current_tenant', $2, false))
			  INSERT INTO engagements(id,tenant_id,name) SELECT $1,$2,'sealed' FROM bound`, []any{eng, tenant}},
			{`INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES ('local-f1',$1,$2,'imported finding')`, []any{tenant, eng}},
			{`SELECT set_config('app.current_tenant', '', false)`, nil},
		} {
			if _, err := db.Exec(q.sql, q.args...); err != nil {
				t.Fatalf("seed %q: %v", q.sql, err)
			}
		}
	})
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)

	// The link as the source instance sealed it, then as the importer stores it: FindingID remapped,
	// SealedFindingID kept, Imported set.
	source := evidence.Evidence{Kind: "finding", FindingID: "source-f1", CreatedBy: "ada", CreatedAt: at, Content: []byte("link")}.Seal()
	imported := source
	imported.ID, imported.EngagementID, imported.FindingID, imported.SealedFindingID, imported.Imported = "imp-1", eng, "local-f1", "source-f1", true
	store := NewEvidenceStore(pool)
	if err := store.Append(ctx, []evidence.Evidence{imported}); err != nil {
		t.Fatalf("append imported link: %v", err)
	}
	items, err := store.ListByEngagement(ctx, eng)
	if err != nil || len(items) != 1 {
		t.Fatalf("list = %v, %v", items, err)
	}
	if got := items[0]; got.FindingID != "local-f1" || got.SealedFindingID != "source-f1" || !got.Imported {
		t.Fatalf("stored link = %+v", got)
	}
	if err := evidence.VerifyChain(items); err != nil {
		t.Fatalf("the remapped link must verify through ListByEngagement: %v", err)
	}

	// Restore verification reads every chain as the restore identity and must see the sealed id too.
	var database string
	if err := owner.QueryRow(`SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("SYNAPSE_TEST_DB_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + database
	admin, err := pgxpool.New(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	restore, err := NewReadOnlyEvidenceStore(context.Background(), admin)
	if err != nil {
		t.Fatalf("restore store: %v", err)
	}
	chains, err := restore.ListEvidenceChains(context.Background())
	if err != nil {
		t.Fatalf("list chains: %v", err)
	}
	var verified bool
	for _, chain := range chains {
		if chain.ID != eng {
			continue
		}
		if err := evidence.VerifyChain(chain.Items); err != nil {
			t.Fatalf("restore read must verify the imported chain: %v (items %+v)", err, chain.Items)
		}
		verified = true
	}
	if !verified {
		t.Fatalf("restore read returned no chain for %s", eng)
	}

	// The marker is append-only: a changed or removed sealed id would read as tampering. The owner is
	// bound to the tenant first, because the forced policy would otherwise match no row and fire no trigger.
	for _, q := range []string{
		`UPDATE evidence_imports SET sealed_finding_id = 'other' WHERE evidence_id = 'imp-1'`,
		`DELETE FROM evidence_imports WHERE evidence_id = 'imp-1'`,
	} {
		tx, err := owner.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant); err != nil {
			t.Fatal(err)
		}
		res, err := tx.Exec(q)
		if err == nil {
			n, _ := res.RowsAffected()
			t.Fatalf("%q succeeded on %d row(s); evidence_imports must be append-only", q, n)
		}
		_ = tx.Rollback()
	}
	// A link sealed here carries no marker and no sealed id.
	native := evidence.Evidence{ID: "nat-1", EngagementID: eng, Kind: "scan", PreviousHash: imported.Hash, CreatedBy: "ada", CreatedAt: at, Content: []byte("native"), SealedFindingID: "ignored"}.Seal()
	if err := store.Append(ctx, []evidence.Evidence{native}); err != nil {
		t.Fatalf("append native link: %v", err)
	}
	var markers int
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM evidence_imports WHERE evidence_id = 'nat-1'`).Scan(&markers)
	}); err != nil || markers != 0 {
		t.Fatalf("native link markers = %d (%v), want 0", markers, err)
	}
}
