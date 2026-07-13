package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFindingRepository(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	eid := shared.ID("ft-" + randHex(t))
	e, err := engagement.New(eid, "", "finding-test", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM findings WHERE engagement_id=$1", eid.String())
		_, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", eid.String())
	})

	repo := NewFindingRepository(pool)
	now := time.Now().UTC().Truncate(time.Second)
	// simulate a finding a human has already triaged to "confirmed"
	f := finding.Finding{
		ID: shared.ID("fid-" + randHex(t)), EngagementID: eid, Title: "CVE-1 in x@1", Severity: shared.SeverityHigh,
		Status: finding.StatusConfirmed, DedupKey: "vuln:CVE-1:x:1", Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// a re-scan re-derives the same finding (new id, StatusOpen, higher severity, later time):
	// dedup → one row; severity updates; but human triage status + created_at are preserved.
	f2 := f
	f2.ID = shared.ID("fid-" + randHex(t))
	f2.Status = finding.StatusOpen
	f2.Severity = shared.SeverityCritical
	f2.Audit.CreatedAt = now.Add(time.Hour)
	if err := repo.Upsert(ctx, []finding.Finding{f2}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}

	list, err := repo.ListByEngagement(ctx, eid)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 deduped finding, got %d", len(list))
	}
	if list[0].Severity != shared.SeverityCritical {
		t.Errorf("severity should update to critical, got %v", list[0].Severity)
	}
	if list[0].Status != finding.StatusConfirmed {
		t.Errorf("human triage status should be preserved as confirmed, got %v", list[0].Status)
	}
	if !list[0].Audit.CreatedAt.Equal(now) {
		t.Errorf("created_at should be preserved, got %v want %v", list[0].Audit.CreatedAt, now)
	}
	if list[0].ID != f.ID {
		t.Errorf("original finding id should be preserved on conflict, got %s want %s", list[0].ID, f.ID)
	}

	// risk ordering: a KEV finding (lower severity, higher risk) must rank first,
	// and kev / risk_score round-trip.
	kevF := finding.Finding{
		ID: shared.ID("fid-" + randHex(t)), EngagementID: eid, Title: "KEV finding", Severity: shared.SeverityMedium,
		Status: finding.StatusOpen, DedupKey: "vuln:CVE-KEV:y:1", KEV: true, RiskScore: 8.0,
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Upsert(ctx, []finding.Finding{kevF}); err != nil {
		t.Fatalf("upsert kev finding: %v", err)
	}
	ranked, err := repo.ListByEngagement(ctx, eid)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranked) != 2 || ranked[0].ID != kevF.ID {
		t.Errorf("KEV finding must rank first regardless of severity; got %+v", ranked)
	}
	if !ranked[0].KEV || ranked[0].RiskScore != 8.0 {
		t.Errorf("kev/risk_score round-trip failed: KEV=%v risk=%v", ranked[0].KEV, ranked[0].RiskScore)
	}

	// RuleKey round-trip and validation
	fRule := finding.Finding{
		ID: shared.ID("fid-" + randHex(t)), EngagementID: eid, Title: "RuleKey test", Kind: finding.KindSAST,
		Severity: shared.SeverityMedium, Status: finding.StatusOpen, DedupKey: "sast:my-rule:a.go:1",
		RuleKey: "my-rule", Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Upsert(ctx, []finding.Finding{fRule}); err != nil {
		t.Fatalf("upsert rulekey finding: %v", err)
	}
	ranked, _ = repo.ListByEngagement(ctx, eid)
	var foundRule *finding.Finding
	for i := range ranked {
		if ranked[i].ID == fRule.ID {
			foundRule = &ranked[i]
		}
	}
	if foundRule == nil || foundRule.RuleKey != "my-rule" {
		t.Errorf("RuleKey round-trip failed: want my-rule, got %q", foundRule.RuleKey)
	}

	// Validation rejection on invalid batch
	badRule := finding.Finding{
		ID: shared.ID("fid-" + randHex(t)), EngagementID: eid, Kind: finding.KindSAST,
		DedupKey: "sast:bad", RuleKey: "",
	}
	if err := repo.Upsert(ctx, []finding.Finding{badRule}); err == nil {
		t.Error("expected Upsert to fail atomic validation due to empty RuleKey, but succeeded")
	}
}
