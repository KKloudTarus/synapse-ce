package postgres

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func TestOwnershipSourceBindingAtomicityAndProducerObligations(t *testing.T) {
	f := newOwnershipFixture(t)
	for _, table := range []string{"ownership_sources", "ownership_source_snapshots", "ownership_finding_sources", "ownership_dirty_findings"} {
		requireMigrationRLS(t, f.ddl, table)
	}
	snapshot := f.snapshot
	snapshot.ID = "captured"
	snapshot.Trust, snapshot.ApprovedBy = "untrusted", ""
	source := ports.OwnershipSourceRecord{ID: "source", EngagementID: "own-a-eng", Repository: "repo", Revision: snapshot.Revision, CreatedBy: "alice", CreatedAt: f.at, Snapshots: []ownership.Snapshot{snapshot}}
	if err := f.repo.SaveOwnershipSource(f.ctx, source); err != nil {
		t.Fatal(err)
	}
	bad := source
	bad.ID = "rolled-back-source"
	if err := f.repo.SaveOwnershipSource(f.ctx, bad); err == nil {
		t.Fatal("duplicate snapshot did not abort source capture")
	}
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM ownership_sources WHERE id='rolled-back-source'`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatal("source header escaped rollback")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	repo := NewFindingRepository(f.pool)
	item := finding.Finding{ID: "canonical", EngagementID: "own-a-eng", DedupKey: "source-finding", Title: "Finding", Kind: finding.KindSAST, RuleKey: "synapse:ownership-test", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Audit: shared.Audit{CreatedAt: f.at, UpdatedAt: f.at}}
	batch := ports.OwnershipSourceBatch{Source: source, Findings: map[string]ports.OwnershipFindingSource{item.DedupKey: {Paths: []string{"src/payment.go"}}}}
	ctx := ports.WithOwnershipSource(f.ctx, batch)
	if err := repo.Upsert(ctx, []finding.Finding{item}); err != nil {
		t.Fatal(err)
	}
	item.ID = "scanner-retry-id"
	if err := repo.Upsert(ctx, []finding.Finding{item}); err != nil {
		t.Fatal(err)
	}
	var initialGeneration int64
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		var id, revision string
		if err := tx.QueryRow(f.ctx, `SELECT b.finding_id,s.source_revision FROM ownership_finding_sources b JOIN ownership_sources s ON s.tenant_id=b.tenant_id AND s.engagement_id=b.engagement_id AND s.id=b.source_id WHERE b.finding_id='canonical'`).Scan(&id, &revision); err != nil {
			return err
		}
		if id != "canonical" || revision != source.Revision {
			t.Fatalf("dedup binding=%s %s", id, revision)
		}
		return tx.QueryRow(f.ctx, `SELECT generation FROM ownership_dirty_findings WHERE finding_id='canonical'`).Scan(&initialGeneration)
	}); err != nil {
		t.Fatal(err)
	}
	item.Description = "Description-only writeup"
	if err := repo.Upsert(ctx, []finding.Finding{item}); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		var generation int64
		if err := tx.QueryRow(f.ctx, `SELECT generation FROM ownership_dirty_findings WHERE finding_id='canonical'`).Scan(&generation); err != nil {
			return err
		}
		if generation != initialGeneration {
			t.Fatalf("description rerouted finding: %d -> %d", initialGeneration, generation)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A different canonical producer still creates a durable obligation without
	// a scan callback; its unavailable source cannot be guessed from free text.
	for _, kind := range []finding.Kind{finding.KindManual, finding.KindSCA, finding.KindSAST, finding.KindSecret, finding.KindMisconfig, finding.KindDAST, finding.KindCloudPosture, finding.KindExploitation, finding.KindThreat} {
		item.ID = shared.ID("producer-" + string(kind))
		item.Kind, item.DedupKey = kind, "producer-"+string(kind)
		item.RuleKey = ""
		if kind.IsRuleBased() {
			item.RuleKey = "synapse:ownership-test"
		}
		if err := repo.Upsert(f.ctx, []finding.Finding{item}); err != nil {
			t.Fatal(err)
		}
		if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
			var n int
			if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM ownership_dirty_findings WHERE finding_id=$1`, item.ID).Scan(&n); err != nil {
				return err
			}
			if n != 1 {
				t.Fatalf("producer %s lost obligation", kind)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Missing/foreign source headers fail in the SAME transaction as the finding.
	item.ID, item.DedupKey = "must-rollback", "must-rollback"
	batch.Source.ID = "foreign-source"
	batch.Findings = map[string]ports.OwnershipFindingSource{item.DedupKey: {Paths: []string{"src/file.go"}}}
	if err := repo.Upsert(ports.WithOwnershipSource(f.ctx, batch), []finding.Finding{item}); err == nil {
		t.Fatal("missing source accepted")
	}
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM findings WHERE id='must-rollback'`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatal("finding escaped source rollback")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
