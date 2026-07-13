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

	// RuleKey enhancements:
	// Mixed valid/invalid batch prevents partial inserts.
	fidValid := shared.ID("fid-" + randHex(t))
	fidInvalid := shared.ID("fid-" + randHex(t))
	validF := finding.Finding{ID: fidValid, EngagementID: eid, Kind: finding.KindSAST, DedupKey: "sast:valid", RuleKey: "valid"}
	invalidF := finding.Finding{ID: fidInvalid, EngagementID: eid, Kind: finding.KindSAST, DedupKey: "sast:invalid", RuleKey: ""}
	if err := repo.Upsert(ctx, []finding.Finding{validF, invalidF}); err == nil {
		t.Error("expected Upsert to fail atomic validation due to empty RuleKey, but succeeded")
	}
	// Verify neither were inserted
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM findings WHERE id IN ($1, $2)", fidValid, fidInvalid).Scan(&count); err != nil {
		t.Fatalf("count partial rows: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 partial rows, got %d", count)
	}

	// Non-rule findings with empty RuleKey persist normally.
	// Non-rule findings with non-empty RuleKey are rejected.
	nonRuleValid := finding.Finding{ID: shared.ID("fid-" + randHex(t)), EngagementID: eid, Kind: finding.KindSCA, DedupKey: "sca:1", RuleKey: ""}
	nonRuleInvalid := finding.Finding{ID: shared.ID("fid-" + randHex(t)), EngagementID: eid, Kind: finding.KindManual, DedupKey: "manual:1", RuleKey: "bad"}
	if err := repo.Upsert(ctx, []finding.Finding{nonRuleValid}); err != nil {
		t.Errorf("non-rule finding with empty RuleKey should persist, got %v", err)
	}
	if err := repo.Upsert(ctx, []finding.Finding{nonRuleInvalid}); err == nil {
		t.Error("non-rule finding with non-empty RuleKey should be rejected")
	}

	// Conflict healing: legacy rule-based rows with a blank RuleKey can still be read.
	// A new scan with a valid RuleKey heals the missing key while preserving existing triage fields.
	fidLegacy := shared.ID("fid-" + randHex(t))
	_, err = pool.Exec(ctx,
		`INSERT INTO findings (id, tenant_id, engagement_id, title, description, severity, cvss_vector, cwe, status, evidence_score, dedup_key, kev, risk_score, created_at, updated_at, sources, confidence, class, scope, reachability, impact, priority, kind, assignee, version, proposed_by, class_reachability, rule_key)
		 VALUES ($1, '', $2, 'legacy', '', 'medium', '', '', 'confirmed', 50, 'sast:legacy', false, 0, $3, $3, '', '', '', '', '', '', 3, 'sast', 'alice', 1, '', '', '')`,
		fidLegacy, eid, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	// Read legacy row
	legacyList, _ := repo.ListByEngagement(ctx, eid)
	var readLegacy *finding.Finding
	for i := range legacyList {
		if legacyList[i].ID == fidLegacy {
			readLegacy = &legacyList[i]
		}
	}
	if readLegacy == nil || readLegacy.RuleKey != "" {
		t.Errorf("expected to read legacy row with empty RuleKey, got %+v", readLegacy)
	}

	// Scan heals it
	healedF := finding.Finding{ID: fidLegacy, EngagementID: eid, Kind: finding.KindSAST, DedupKey: "sast:legacy", RuleKey: "healed-rule"}
	if err := repo.Upsert(ctx, []finding.Finding{healedF}); err != nil {
		t.Fatalf("upsert to heal legacy row: %v", err)
	}

	list2, _ := repo.ListByEngagement(ctx, eid)
	var healed *finding.Finding
	for i := range list2 {
		if list2[i].ID == fidLegacy {
			healed = &list2[i]
		}
	}
	if healed == nil || healed.RuleKey != "healed-rule" {
		t.Errorf("conflict upsert should update RuleKey, got %q", healed.RuleKey)
	}
	if healed.Status != finding.StatusConfirmed || healed.Assignee != "alice" || healed.EvidenceScore != 50 {
		t.Errorf("triage fields should be preserved: status=%v, assignee=%v, evidence=%v", healed.Status, healed.Assignee, healed.EvidenceScore)
	}

	// Triage methods correctly return and preserve the finding's RuleKey.
	fUpd, err := repo.UpdateStatus(ctx, eid, fidLegacy, finding.StatusFalsePos, healed.Version)
	if err != nil || fUpd.RuleKey != "healed-rule" {
		t.Errorf("UpdateStatus must preserve RuleKey, got %q (err: %v)", fUpd.RuleKey, err)
	}
	fUpd, err = repo.SetAssignee(ctx, eid, fidLegacy, "charlie", fUpd.Version)
	if err != nil || fUpd.RuleKey != "healed-rule" {
		t.Errorf("SetAssignee must preserve RuleKey, got %q (err: %v)", fUpd.RuleKey, err)
	}
	fUpd, err = repo.SetEvidenceScore(ctx, eid, fidLegacy, 90, fUpd.Version)
	if err != nil || fUpd.RuleKey != "healed-rule" {
		t.Errorf("SetEvidenceScore must preserve RuleKey, got %q (err: %v)", fUpd.RuleKey, err)
	}
}
