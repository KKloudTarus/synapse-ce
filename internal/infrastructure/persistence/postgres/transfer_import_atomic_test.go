package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	transferuc "github.com/KKloudTarus/synapse-ce/internal/usecase/transfer"
)

type failingImportAudit struct{ log *AuditLog }

func (a failingImportAudit) Record(ctx context.Context, e ports.AuditEntry) error {
	if e.Action == "engagement.imported" {
		return errors.New("audit store unavailable")
	}
	return a.log.Record(ctx, e)
}

// TestImportIsOneTransactionOnPostgres (#1722): evidence is append-only, so an import that fails after
// its evidence is written cannot be deleted afterwards. Under the tenant transaction runner the
// engagement, findings, evidence and audit entry commit together: a failed audit append leaves no row,
// and a working one leaves all of them, with a finding-linked link under the imported finding.
func TestImportIsOneTransactionOnPostgres(t *testing.T) {
	const tenant = "transfer-atomic"
	pool, _ := ownershipMigrationDatabase(t, 282, 0, func(db *sql.DB) {
		if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES ($1,$1)`, tenant); err != nil {
			t.Fatal(err)
		}
	})
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	clock := &notificationTestClock{at: at}
	build := func(audit ports.AuditLogger) (*transferuc.Service, *evidenceuc.Service) {
		ev, err := evidenceuc.NewService(NewEvidenceStore(pool), blob.NewMemory(), audit, clock, &notificationTestIDs{n: 100})
		if err != nil {
			t.Fatal(err)
		}
		svc, err := transferuc.NewService(NewEngagementRepository(pool), NewFindingRepository(pool), NewCommentRepository(pool), ev, audit, clock, &notificationTestIDs{n: 200})
		if err != nil {
			t.Fatal(err)
		}
		svc.SetTransactionRunner(NewTenantTransactionRunner(pool))
		return svc, ev
	}

	// A bundle as another instance exported it: one finding and a chain of two links, one tied to it.
	source, err := engagement.New("src-eng", "src-tenant", "source", "Acme", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.SetScope([]engagement.Target{{Kind: engagement.TargetDomain, Value: "example.com"}}, nil, at); err != nil {
		t.Fatal(err)
	}
	first := evidence.Evidence{ID: "src-ev-1", EngagementID: "src-eng", Kind: "scan", Content: []byte("scan"), CreatedBy: "ada", CreatedAt: at}.Seal()
	second := evidence.Evidence{ID: "src-ev-2", EngagementID: "src-eng", FindingID: "src-f1", Kind: "finding", Content: []byte("finding"), PreviousHash: first.Hash, CreatedBy: "ada", CreatedAt: at}.Seal()
	bundle := transferuc.Bundle{
		Version: transferuc.BundleVersionFramed, ExportedAt: at, Engagement: source,
		Findings: []finding.Finding{{ID: "src-f1", EngagementID: "src-eng", Title: "XSS", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: "manual:src-f1"}},
		Evidence: []evidence.Evidence{first, second}, EvidenceHead: second.Hash,
	}
	count := func(query string) int {
		var n int
		if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error { return tx.QueryRow(ctx, query).Scan(&n) }); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return n
	}

	failing, _ := build(failingImportAudit{log: NewAuditLog(pool)})
	if _, err := failing.Import(ctx, "alice", tenant, bundle); err == nil {
		t.Fatal("import must fail when its audit record cannot be written")
	}
	if n := count(`SELECT count(*) FROM engagements`); n != 0 {
		t.Fatalf("%d engagement(s) left after a failed import", n)
	}
	if n := count(`SELECT count(*) FROM evidence`); n != 0 {
		t.Fatalf("%d evidence row(s) left after a failed import", n)
	}

	working, ev := build(NewAuditLog(pool))
	imported, err := working.Import(ctx, "alice", tenant, bundle)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if n := count(`SELECT count(*) FROM audit_log WHERE action = 'engagement.imported'`); n != 1 {
		t.Fatalf("engagement.imported rows = %d, want 1", n)
	}
	rep, err := ev.Verify(ctx, imported.ID)
	if err != nil || !rep.Intact || rep.Verified != 2 {
		t.Fatalf("imported chain = %+v, %v", rep, err)
	}
	for _, link := range rep.Items {
		if link.Kind != "finding" {
			continue
		}
		if link.SealedFindingID != "src-f1" || link.FindingID == "" || link.FindingID == "src-f1" || !link.Imported {
			t.Fatalf("finding-linked link = %+v, want the sealed id kept and a remapped FindingID", link)
		}
	}
}
