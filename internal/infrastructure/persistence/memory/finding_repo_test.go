package memory

import (
	"context"
	"errors"
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

func TestFindingRepositoryUpsertVersionOnlyChangesForMachineProjection(t *testing.T) {
	repo := NewFindingRepository()
	ctx := context.Background()
	initial := finding.Finding{
		ID: "f-version", EngagementID: "e-version", Title: "old", Severity: shared.SeverityMedium,
		Status: finding.StatusConfirmed, DedupKey: "vuln:version", Version: 1,
	}
	if err := repo.Upsert(ctx, []finding.Finding{initial}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Upsert(ctx, []finding.Finding{initial}); err != nil {
		t.Fatal(err)
	}
	list, err := repo.ListByEngagement(ctx, initial.EngagementID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list after replay: len=%d err=%v", len(list), err)
	}
	if list[0].Version != 1 {
		t.Fatalf("identical replay bumped version to %d", list[0].Version)
	}

	changed := initial
	changed.Title = "new"
	if err := repo.Upsert(ctx, []finding.Finding{changed}); err != nil {
		t.Fatal(err)
	}
	list, err = repo.ListByEngagement(ctx, initial.EngagementID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list after change: len=%d err=%v", len(list), err)
	}
	if list[0].Version != 2 || list[0].Title != "new" || list[0].Status != finding.StatusConfirmed {
		t.Fatalf("machine change/version/triage mismatch: %+v", list[0])
	}
	if _, err := repo.UpdateStatus(ctx, initial.EngagementID, initial.ID, finding.StatusFalsePos, 1); err == nil {
		t.Fatal("stale analyst update succeeded after automated change")
	} else if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale analyst update error=%v, want conflict", err)
	}
}

func TestFindingRepositoryDeepCopiesDataFlow(t *testing.T) {
	repo := NewFindingRepository()
	column := 4
	source := finding.SourceLocation{File: "app.py", StartLine: 3, EndLine: 3, StartColumn: &column, EndColumn: &column}
	sink := finding.SourceLocation{File: "app.py", StartLine: 4, EndLine: 4, StartColumn: &column, EndColumn: &column}
	item := finding.Finding{
		ID: "f-flow", EngagementID: "e-flow", Kind: finding.KindSAST, RuleKey: "python-taint-command", DedupKey: "sast:ai:j-flow",
		DataFlow:       &finding.DataFlowTrace{Language: "python", Source: source, Sink: sink, Steps: []finding.SourceLocation{source, sink}},
		SourceLocation: &sink,
	}
	if err := repo.Upsert(context.Background(), []finding.Finding{item}); err != nil {
		t.Fatal(err)
	}
	item.DataFlow.Steps[0].File = "caller-mutated.py"
	item.SourceLocation.File = "caller-mutated.py"
	got, err := repo.GetByEngagementAndID(context.Background(), "e-flow", "f-flow")
	if err != nil {
		t.Fatal(err)
	}
	if got.DataFlow.Steps[0].File != "app.py" || got.SourceLocation.File != "app.py" {
		t.Fatalf("stored finding was mutated through input: %+v", got)
	}
	got.DataFlow.Steps[0].File = "reader-mutated.py"
	again, _ := repo.GetByEngagementAndID(context.Background(), "e-flow", "f-flow")
	if again.DataFlow.Steps[0].File != "app.py" {
		t.Fatalf("stored finding was mutated through output: %+v", again)
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

func TestCloudFindingVisibilityFollowsActiveObservation(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	repo := NewFindingRepository()
	observations := NewCloudObservationStore()
	repo.SetCloudObservationStore(observations)
	cloudFinding := finding.Finding{
		ID: "cloud-1", EngagementID: "eng", Title: "public bucket", Severity: shared.SeverityHigh,
		Status: finding.StatusOpen, Kind: finding.KindCloudPosture, RuleKey: "cloud-storage-public",
		DedupKey: "cspm:aws:scope:cloud-storage-public:bucket:public", ProposedBy: "cspm", EvidenceScore: finding.EvidenceThreshold,
	}
	if err := repo.Upsert(ctx, []finding.Finding{cloudFinding}); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.ListByEngagement(ctx, "eng"); len(got) != 0 {
		t.Fatalf("unobserved cloud finding visible: %#v", got)
	}
	if err := observations.ReconcileCloudObservations(ctx, "tenant", "eng", "cspm:scope", "evidence", nil, []shared.ID{"cloud-1"}, nil, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.ListByEngagement(ctx, "eng"); len(got) != 1 {
		t.Fatalf("active cloud finding hidden: %#v", got)
	}
	if got, _ := repo.ListPublishableByEngagement(ctx, "eng"); len(got) != 1 {
		t.Fatalf("active publishable cloud finding hidden: %#v", got)
	}
	if err := observations.ReconcileCloudObservations(ctx, "tenant", "eng", "cspm:scope", "evidence-2", nil, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.ListByEngagement(ctx, "eng"); len(got) != 0 {
		t.Fatalf("inactive cloud finding visible: %#v", got)
	}
	if got, _ := repo.ListPublishableByEngagement(ctx, "eng"); len(got) != 0 {
		t.Fatalf("inactive cloud finding publishable: %#v", got)
	}
}

// The two summaries agree on what "open" means (no false positives, no remediated, no licence
// records) and differ only in kind: the vulnerability summary is SCA only, the finding summary counts
// every kind the engagement list shows.
func TestFindingRepositorySummarizesOpenFindingsByEngagement(t *testing.T) {
	ctx := context.Background()
	repo := NewFindingRepository()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	mk := func(id, dedup string, kind finding.Kind, sev shared.Severity, status finding.Status) finding.Finding {
		f := finding.Finding{ID: shared.ID(id), EngagementID: "eng-1", Kind: kind, DedupKey: dedup, Title: id, Severity: sev, Status: status, FixedVersion: "1.2", Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
		if kind != finding.KindSCA {
			f.RuleKey = "rule-" + id // code findings carry the rule that produced them
		}
		return f
	}
	if err := repo.Upsert(ctx, []finding.Finding{
		mk("f1", "vuln:CVE-1:a:1", finding.KindSCA, shared.SeverityCritical, finding.StatusOpen),
		mk("f2", "vuln:CVE-2:b:1", finding.KindSCA, shared.SeverityHigh, finding.StatusRemediated),
		mk("f3", "vuln:CVE-3:c:1", finding.KindSCA, shared.SeverityHigh, finding.StatusFalsePos),
		mk("f4", "license:GPL:d:1", finding.KindSCA, shared.SeverityLow, finding.StatusOpen),
		mk("f5", "sast:rule:e.go:1", finding.KindSAST, shared.SeverityMedium, finding.StatusConfirmed),
		mk("f6", "secret:aws:f.env:1", finding.KindSecret, shared.SeverityHigh, finding.StatusOpen),
	}); err != nil {
		t.Fatal(err)
	}

	vulns, err := repo.SummarizeVulnerabilitiesByEngagements(ctx, []shared.ID{"eng-1", "eng-none"})
	if err != nil {
		t.Fatal(err)
	}
	if v := vulns["eng-1"]; v.Total != 1 || v.Critical != 1 || v.Fixable != 1 {
		t.Fatalf("vulnerability summary = %+v, want the one open SCA finding", v)
	}
	if v := vulns["eng-none"]; v.Total != 0 {
		t.Fatalf("unknown engagement summary = %+v", v)
	}
	all, err := repo.SummarizeOpenFindingsByEngagements(ctx, []shared.ID{"eng-1"})
	if err != nil {
		t.Fatal(err)
	}
	if a := all["eng-1"]; a.Total != 3 || a.Critical != 1 || a.High != 1 || a.Medium != 1 {
		t.Fatalf("open finding summary = %+v, want SCA + SAST + secret", a)
	}
}
