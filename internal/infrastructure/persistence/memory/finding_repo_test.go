package memory

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFindingRepositoryUpsertDedup(t *testing.T) {
	r := NewFindingRepository()
	ctx := context.Background()

	f := finding.Finding{ID: "f1", EngagementID: "e1", Title: "v1", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: "vuln:CVE-1"}
	if err := r.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatal(err)
	}

	// re-upsert the same dedup with a higher severity and a different status:
	// dedup → one row; severity updates; triage status is preserved (stays open).
	f2 := f
	f2.Severity = shared.SeverityCritical
	f2.Status = finding.StatusConfirmed
	if err := r.Upsert(ctx, []finding.Finding{f2}); err != nil {
		t.Fatal(err)
	}

	list, err := r.ListByEngagement(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 deduped finding, got %d", len(list))
	}
	if list[0].Severity != shared.SeverityCritical {
		t.Errorf("severity should update to critical, got %v", list[0].Severity)
	}
	if list[0].Status != finding.StatusOpen {
		t.Errorf("triage status should be preserved as open, got %v", list[0].Status)
	}

	// other engagements isolated
	if l, _ := r.ListByEngagement(ctx, "other"); len(l) != 0 {
		t.Errorf("other engagement should have no findings, got %d", len(l))
	}
}

func TestFindingRepositoryRuleKey(t *testing.T) {
	r := NewFindingRepository()
	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Validation rejection of batch with one invalid
	valid := finding.Finding{ID: "f1", EngagementID: "e1", Kind: finding.KindSAST, RuleKey: "good", DedupKey: "sast:good:1"}
	invalid := finding.Finding{ID: "f2", EngagementID: "e1", Kind: finding.KindSAST, RuleKey: "bad ", DedupKey: "sast:bad:2"} // space
	err := r.Upsert(ctx, []finding.Finding{valid, invalid})
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected validation error for invalid batch, got %v", err)
	}
	l, _ := r.ListByEngagement(ctx, "e1")
	if len(l) != 0 {
		t.Errorf("repository should be empty after failed batch, got %d", len(l))
	}

	// 2. Non-rule finding with RuleKey rejected
	nonRule := finding.Finding{ID: "f3", EngagementID: "e1", Kind: finding.KindSCA, RuleKey: "should-be-empty", DedupKey: "sca:1"}
	if err := r.Upsert(ctx, []finding.Finding{nonRule}); err == nil {
		t.Error("non-rule finding with RuleKey should be rejected")
	}

	// 3. Conflict healing: legacy blank RuleKey gets updated by new upsert
	// Simulate legacy blank by directly injecting it with some triage fields
	r.data["e1"] = map[string]finding.Finding{}
	r.data["e1"]["sast:legacy:main.go:2"] = finding.Finding{
		ID: "f4", EngagementID: "e1", Kind: finding.KindSAST, DedupKey: "sast:legacy:main.go:2",
		RuleKey: "", // legacy blank
		Status:  finding.StatusConfirmed, Assignee: "alice", EvidenceScore: 100, Audit: shared.Audit{CreatedAt: now},
	}

	// Scanner re-runs and upserts with the correct key
	f4Scan := finding.Finding{
		ID: "f4", EngagementID: "e1", Kind: finding.KindSAST, DedupKey: "sast:legacy:main.go:2",
		RuleKey: "legacy-rule",
	}
	if err := r.Upsert(ctx, []finding.Finding{f4Scan}); err != nil {
		t.Fatal(err)
	}

	list, _ := r.ListByEngagement(ctx, "e1")
	var healed *finding.Finding
	for i := range list {
		if list[i].ID == "f4" {
			healed = &list[i]
		}
	}
	if healed == nil {
		t.Fatal("expected healed finding")
	}
	if healed.RuleKey != "legacy-rule" {
		t.Errorf("RuleKey should heal on conflict, got %q", healed.RuleKey)
	}
	if healed.Status != finding.StatusConfirmed || healed.Assignee != "alice" || healed.EvidenceScore != 100 || !healed.Audit.CreatedAt.Equal(now) {
		t.Errorf("triage fields should be preserved, got %+v", healed)
	}

	// 4. Update methods do not lose RuleKey
	fUpd, err := r.UpdateStatus(ctx, "e1", "f4", finding.StatusFalsePos, healed.Version)
	if err != nil || fUpd.RuleKey != "legacy-rule" {
		t.Errorf("UpdateStatus must preserve RuleKey, got %q (err: %v)", fUpd.RuleKey, err)
	}
	fUpd, err = r.SetAssignee(ctx, "e1", "f4", "charlie", fUpd.Version)
	if err != nil || fUpd.RuleKey != "legacy-rule" {
		t.Errorf("SetAssignee must preserve RuleKey, got %q (err: %v)", fUpd.RuleKey, err)
	}
	fUpd, err = r.SetEvidenceScore(ctx, "e1", "f4", 50, fUpd.Version)
	if err != nil || fUpd.RuleKey != "legacy-rule" {
		t.Errorf("SetEvidenceScore must preserve RuleKey, got %q (err: %v)", fUpd.RuleKey, err)
	}
}
