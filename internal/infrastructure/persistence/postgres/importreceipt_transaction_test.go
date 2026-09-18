package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importreceipt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestImportReceiptRepositoryParticipatesInTenantTransaction(t *testing.T) {
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

	const tenant = "t-receipt-tx"
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_ = WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
			_, _ = tx.Exec(context.Background(), `DELETE FROM imported_findings WHERE tenant_id=$1`, tenant)
			_, _ = tx.Exec(context.Background(), `DELETE FROM import_receipts WHERE tenant_id=$1`, tenant)
			return nil
		})
	})

	now := time.Now().UTC().Truncate(time.Millisecond)
	pending := importreceipt.Receipt{
		ID: "run-tx", TenantID: tenant, EngagementID: "eng-tx",
		SourceIdentity: "sarif", Digest: "sha256:tx", ParserVersion: "sarif-2.1.0/v1",
		Outcome: importreceipt.OutcomePending,
		CreatedAt: now, UpdatedAt: now,
	}
	finding := importedfinding.ImportedFinding{
		ID: "if-tx", TenantID: tenant, EngagementID: "eng-tx",
		Severity: shared.SeverityHigh, Title: "external result", Message: "m",
		Location: importedfinding.Location{Path: "src/app.go", StartLine: 7},
		Provenance: importedfinding.Provenance{
			ToolName: "semgrep", ToolVersion: "1.2.3", RuleID: "rule.tx", SourceDigest: pending.Digest,
			IngestedBy: "human:test", IngestedAt: now,
		},
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}

	receipts := NewImportReceiptRepository(pool)
	findings := NewImportedFindingRepository(pool)
	transactions := NewTenantTransactionRunner(pool)
	finalAt := now.Add(time.Second)
	finalCounters := importreceipt.Counters{Accepted: 1}

	persistAll := func(txCtx context.Context) error {
		if _, created, err := receipts.CreateOrGet(txCtx, tenant, pending); err != nil {
			return err
		} else if !created {
			return errors.New("receipt unexpectedly existed")
		}
		if stored, existing, err := findings.Save(txCtx, tenant, []importedfinding.ImportedFinding{finding}); err != nil {
			return err
		} else if stored != 1 || existing != 0 {
			return errors.New("finding was not newly stored")
		}
		_, err := receipts.Finalize(txCtx, tenant, pending.ID, importreceipt.OutcomeComplete, finalCounters, finalAt)
		return err
	}

	rollback := errors.New("force composite rollback")
	err = transactions.Run(ctx, tenant, func(txCtx context.Context) error {
		if err := persistAll(txCtx); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("rollback transaction err = %v, want sentinel", err)
	}
	if _, err := receipts.GetByIdentity(ctx, tenant, pending.EngagementID, pending.SourceIdentity, pending.Digest); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("receipt survived rollback: %v", err)
	}
	rows, err := findings.ListByEngagement(ctx, tenant, pending.EngagementID)
	if err != nil {
		t.Fatalf("list findings after rollback: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("%d imported findings survived rollback", len(rows))
	}

	if err := transactions.Run(ctx, tenant, persistAll); err != nil {
		t.Fatalf("commit composite transaction: %v", err)
	}
	got, err := receipts.GetByIdentity(ctx, tenant, pending.EngagementID, pending.SourceIdentity, pending.Digest)
	if err != nil {
		t.Fatalf("read committed receipt: %v", err)
	}
	if got.Outcome != importreceipt.OutcomeComplete || got.Counters != finalCounters {
		t.Fatalf("committed receipt = %+v", got)
	}
	rows, err = findings.ListByEngagement(ctx, tenant, pending.EngagementID)
	if err != nil {
		t.Fatalf("list committed findings: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != finding.ID {
		t.Fatalf("committed imported findings = %+v", rows)
	}
}
