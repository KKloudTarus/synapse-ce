package memory

import (
	"context"
	"strings"
	"testing"

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

	// 1. Initial insert with RuleKey
	f1 := finding.Finding{
		ID: "f1", EngagementID: "e1", Title: "SAST issue", Kind: finding.KindSAST,
		RuleKey: "go:sql-injection", DedupKey: "sast:go:sql-injection:main.go:1",
	}
	if err := r.Upsert(ctx, []finding.Finding{f1}); err != nil {
		t.Fatal(err)
	}

	list, _ := r.ListByEngagement(ctx, "e1")
	if len(list) != 1 || list[0].RuleKey != "go:sql-injection" {
		t.Fatalf("want RuleKey 'go:sql-injection', got %+v", list)
	}

	// 2. Conflict healing: legacy blank RuleKey gets updated by new upsert
	// Simulate legacy blank by directly injecting it
	r.data["e1"]["sast:legacy:main.go:2"] = finding.Finding{
		ID: "f2", EngagementID: "e1", Kind: finding.KindSAST, DedupKey: "sast:legacy:main.go:2",
		RuleKey: "", // legacy blank
	}

	// Scanner re-runs and upserts with the correct key
	f2 := finding.Finding{
		ID: "f2", EngagementID: "e1", Kind: finding.KindSAST, DedupKey: "sast:legacy:main.go:2",
		RuleKey: "legacy-rule",
	}
	if err := r.Upsert(ctx, []finding.Finding{f2}); err != nil {
		t.Fatal(err)
	}

	list, _ = r.ListByEngagement(ctx, "e1")
	var healed *finding.Finding
	for i := range list {
		if list[i].ID == "f2" {
			healed = &list[i]
		}
	}
	if healed == nil || healed.RuleKey != "legacy-rule" {
		t.Errorf("RuleKey should heal on conflict, got %q", healed.RuleKey)
	}

	// 3. Validation rejection
	bad := finding.Finding{
		ID: "f3", EngagementID: "e1", Kind: finding.KindSecret, DedupKey: "secret:bad",
		RuleKey: " bad ", // invalid spaces
	}
	err := r.Upsert(ctx, []finding.Finding{bad})
	if err == nil || !strings.Contains(err.Error(), "rule key is invalid") {
		t.Errorf("expected validation error, got %v", err)
	}
}
