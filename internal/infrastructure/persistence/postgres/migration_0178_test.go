package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importreceipt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func postgresTestImportReceipt(id, tenant string) importreceipt.Receipt {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return importreceipt.Receipt{
		ID: shared.ID(id), TenantID: shared.ID(tenant), EngagementID: "eng-receipt",
		SourceIdentity: "sarif", Digest: "sha256:empty", ParserVersion: "sarif-2.1.0/v1",
		Outcome: importreceipt.OutcomeComplete, Counters: importreceipt.Counters{},
		CreatedAt: now, UpdatedAt: now,
	}
}

func TestImportReceiptsDurabilityRLSAndConcurrentIdempotency(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	var enabled, forced bool
	if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid='import_receipts'::regclass`).Scan(&enabled, &forced); err != nil {
		t.Fatalf("inspect RLS: %v", err)
	}
	if !enabled || !forced {
		t.Fatalf("import_receipts RLS = enabled:%v forced:%v, want both true", enabled, forced)
	}

	for _, tenant := range []string{"t-receipt-a", "t-receipt-b"} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, tenant := range []string{"t-receipt-a", "t-receipt-b"} {
			_ = WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
				_, _ = tx.Exec(context.Background(), `DELETE FROM import_receipts WHERE tenant_id=$1`, tenant)
				return nil
			})
		}
	})
	// The integration pool connects as the PostgreSQL superuser, which bypasses RLS even
	// for FORCE ROW LEVEL SECURITY. Exercise the policy under a non-privileged role.
	const rlsRole = "import_receipt_rls_role_1181"
	for _, stmt := range []string{
		`DROP OWNED BY ` + rlsRole,
		`DROP ROLE IF EXISTS ` + rlsRole,
	} {
		_, _ = pool.Exec(ctx, stmt)
	}
	for _, stmt := range []string{
		`CREATE ROLE ` + rlsRole + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + rlsRole,
		`GRANT SELECT, INSERT ON import_receipts TO ` + rlsRole,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("set up receipt RLS role: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+rlsRole)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+rlsRole)
	})
	underRLSRole := func(tenant string, fn func(pgx.Tx) error) error {
		return WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+rlsRole); err != nil {
				return err
			}
			return fn(tx)
		})
	}

	repo := NewImportReceiptRepository(pool)
	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	type result struct {
		receipt importreceipt.Receipt
		created bool
		err     error
	}
	results := make(chan result, workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			r := postgresTestImportReceipt(fmt.Sprintf("run-%02d", i), "t-receipt-a")
			got, created, err := repo.CreateOrGet(ctx, "t-receipt-a", r)
			results <- result{receipt: got, created: created, err: err}
		}(i)
	}
	wg.Wait()
	close(results)

	createdCount := 0
	var resolved shared.ID
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent create: %v", result.err)
		}
		if result.created {
			createdCount++
		}
		if resolved.IsZero() {
			resolved = result.receipt.ID
		}
		if result.receipt.ID != resolved {
			t.Fatalf("concurrent retries resolved %s and %s", resolved, result.receipt.ID)
		}
	}
	if createdCount != 1 {
		t.Fatalf("created count = %d, want 1", createdCount)
	}

	got, err := repo.GetByIdentity(ctx, "t-receipt-a", "eng-receipt", "sarif", "sha256:empty")
	if err != nil || got.ID != resolved || got.Counters != (importreceipt.Counters{}) {
		t.Fatalf("zero-finding receipt = %+v, %v; want durable %s", got, err, resolved)
	}
	_, err = repo.GetByIdentity(ctx, "t-receipt-b", "eng-receipt", "sarif", "sha256:empty")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant lookup err = %v, want ErrNotFound", err)
	}

	// Prove isolation is the database's RLS answer, not only this repository's tenant predicate.
	if err := underRLSRole("t-receipt-b", func(tx pgx.Tx) error {
		var visible int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM import_receipts WHERE id=$1`, resolved.String()).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			return fmt.Errorf("tenant b can see %d tenant-a receipt rows", visible)
		}
		return nil
	}); err != nil {
		t.Fatalf("RLS read isolation: %v", err)
	}
	if err := underRLSRole("t-receipt-b", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO import_receipts
			(id,tenant_id,engagement_id,source_identity,digest,parser_version,outcome)
			VALUES ('rls-forged','t-receipt-a','eng-receipt','sarif','sha256:forged','v1','complete')`)
		return err
	}); err == nil {
		t.Fatal("RLS WITH CHECK allowed tenant b to insert a tenant-a receipt")
	}

	// The database mirrors the domain rule: refused results cannot be labelled fully complete.
	if err := WithTenant(ctx, pool, "t-receipt-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO import_receipts
			(id,tenant_id,engagement_id,source_identity,digest,parser_version,outcome,refused_count)
			VALUES ('invalid-complete','t-receipt-a','eng-receipt','sarif','sha256:invalid-complete','v1','complete',1)`)
		return err
	}); err == nil {
		t.Fatal("database allowed a complete receipt with refused results")
	}

	pending := postgresTestImportReceipt("run-pending", "t-receipt-a")
	pending.Digest = "sha256:pending"
	pending.Outcome = importreceipt.OutcomePending
	pending, created, err := repo.CreateOrGet(ctx, "t-receipt-a", pending)
	if err != nil || !created {
		t.Fatalf("create pending = created:%v err:%v", created, err)
	}
	counters := importreceipt.Counters{Accepted: 2, Deduplicated: 1, Refused: 3}
	finalAt := pending.CreatedAt.Add(time.Second)
	finalized, err := repo.Finalize(ctx, "t-receipt-a", pending.ID, importreceipt.OutcomePartial, counters, finalAt)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if finalized.Outcome != importreceipt.OutcomePartial || finalized.Counters != counters {
		t.Fatalf("finalized receipt = %+v", finalized)
	}
	if _, err := repo.Finalize(ctx, "t-receipt-a", pending.ID, importreceipt.OutcomePartial, counters, finalAt.Add(time.Second)); err != nil {
		t.Fatalf("same final result must replay cleanly: %v", err)
	}
	if _, err := repo.Finalize(ctx, "t-receipt-a", pending.ID, importreceipt.OutcomeComplete, counters, finalAt.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("terminal rewrite err = %v, want ErrConflict", err)
	}
	invalidCounters := importreceipt.Counters{Accepted: -1}
	if _, err := repo.Finalize(ctx, "t-receipt-a", pending.ID, importreceipt.OutcomePartial, invalidCounters, finalAt.Add(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("invalid terminal rewrite err = %v, want ErrConflict", err)
	}
}

func TestMigration0178UpgradePreservesImportedFindings(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = MigrateLocked(context.Background(), dsn) })

	db := openLockedGooseDB(t, dsn)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.DownTo(db, ".", 177); err != nil {
		t.Fatalf("down to 177: %v", err)
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect at 177: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('t-receipt-upgrade','t-receipt-upgrade') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_ = WithTenant(context.Background(), pool, "t-receipt-upgrade", func(tx pgx.Tx) error {
			_, _ = tx.Exec(context.Background(), `DELETE FROM imported_findings WHERE tenant_id='t-receipt-upgrade'`)
			return nil
		})
	})

	now := time.Now().UTC().Truncate(time.Millisecond)
	preUpgrade := importedfinding.ImportedFinding{
		ID: "if-before-0178", TenantID: "t-receipt-upgrade", EngagementID: "eng-upgrade",
		Severity: shared.SeverityHigh, Title: "t", Message: "m",
		Provenance: importedfinding.Provenance{
			ToolName: "semgrep", ToolVersion: "1.0", RuleID: "rule.a", SourceDigest: "digest-before-0178",
			IngestedBy: "human:test", IngestedAt: now,
		},
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	oldRepo := NewImportedFindingRepository(pool)
	if stored, existing, err := oldRepo.Save(ctx, "t-receipt-upgrade", []importedfinding.ImportedFinding{preUpgrade}); err != nil || stored != 1 || existing != 0 {
		t.Fatalf("seed pre-0178 imported finding = stored:%d existing:%d err:%v", stored, existing, err)
	}

	if err := goose.UpTo(db, ".", 178); err != nil {
		t.Fatalf("up to 178: %v", err)
	}

	repo := NewImportedFindingRepository(pool)
	rows, err := repo.ListByEngagement(ctx, "t-receipt-upgrade", "eng-upgrade")
	if err != nil {
		t.Fatalf("read pre-0178 finding after upgrade: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "if-before-0178" {
		t.Fatalf("pre-0178 data changed across upgrade: %+v", rows)
	}
}
