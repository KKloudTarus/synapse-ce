package businessassetuc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

type testIDs struct{ next int }

func (i *testIDs) NewID() shared.ID { i.next++; return shared.ID(fmt.Sprintf("id-%d", i.next)) }

type testAudit struct{}

func (testAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func newBusinessAssetService(t *testing.T) (*Service, *memory.AssetStore, *memory.EngagementRepository, *memory.FindingRepository, *memory.ImportedFindingStore, *memory.JudgmentStore, testClock) {
	t.Helper()
	clock := testClock{time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)}
	engagements := memory.NewEngagementRepository()
	assets := memory.NewAssetStore()
	findings := memory.NewFindingRepository()
	imported := memory.NewImportedFindingStore()
	judgments := memory.NewJudgmentStore()
	assets.SetEngagementRepository(engagements)
	service, err := NewService(assets, findings, imported, judgments, memory.NewRetestRepository(), testAudit{}, clock, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return service, assets, engagements, findings, imported, judgments, clock
}

func TestPostureNeverDefaultsToCleanWithoutCoverage(t *testing.T) {
	service, _, _, _, _, _, _ := newBusinessAssetService(t)
	created, err := service.Create(context.Background(), CreateInput{TenantID: "t1", Key: "mobile", Name: "Mobile", Type: asset.BusinessAssetApplication, Criticality: asset.CriticalityCritical, Owner: "team", Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	posture, err := service.Posture(context.Background(), "t1", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if posture.Rating != "unknown" {
		t.Fatalf("empty coverage posture=%q, want unknown", posture.Rating)
	}
}

func TestCoverageAndRetiredAssignment(t *testing.T) {
	service, _, engagements, _, _, _, clock := newBusinessAssetService(t)
	ctx := context.Background()
	created, err := service.Create(ctx, CreateInput{TenantID: "t1", Key: "mobile", Name: "Mobile", Type: asset.BusinessAssetApplication, Criticality: asset.CriticalityHigh, Owner: "team", Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagement.New("e1", "t1", "Login", "", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetScope([]engagement.Target{{Kind: engagement.TargetRepo, Value: "repo-1"}}, nil, clock.now); err != nil {
		t.Fatal(err)
	}
	if err := e.Transition(engagement.StatusActive, clock.now); err != nil {
		t.Fatal(err)
	}
	if err := e.Transition(engagement.StatusCompleted, clock.now); err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := service.AssignEngagement(ctx, "t1", e.ID, created.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	coverage, err := service.Coverage(ctx, "t1", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.Counts[CoverageCovered] != 1 {
		t.Fatalf("coverage=%+v, want one covered scope", coverage)
	}
	updated, err := service.Update(ctx, "t1", created.ID, UpdateInput{Name: created.Name, Description: created.Description, Type: created.Type, Criticality: created.Criticality, Owner: created.Owner, Version: created.Version, Lifecycle: asset.BusinessAssetActive, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err = service.Update(ctx, "t1", created.ID, UpdateInput{Name: updated.Name, Description: updated.Description, Type: updated.Type, Criticality: updated.Criticality, Owner: updated.Owner, Version: updated.Version, Lifecycle: asset.BusinessAssetDecommissioning, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err = service.Update(ctx, "t1", created.ID, UpdateInput{Name: updated.Name, Description: updated.Description, Type: updated.Type, Criticality: updated.Criticality, Owner: updated.Owner, Version: updated.Version, Lifecycle: asset.BusinessAssetRetired, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.AssignEngagement(ctx, "t1", e.ID, updated.ID, "alice"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("retired assignment error=%v", err)
	}
}

func TestCoverageDraftHasNoAssessmentTimestamp(t *testing.T) {
	service, _, engagements, _, _, _, clock := newBusinessAssetService(t)
	ctx := context.Background()
	created, err := service.Create(ctx, CreateInput{TenantID: "t1", Key: "mobile", Name: "Mobile", Type: asset.BusinessAssetApplication, Criticality: asset.CriticalityHigh, Owner: "team", Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagement.New("e-draft", "t1", "Draft assessment", "", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetScope([]engagement.Target{{Kind: engagement.TargetRepo, Value: "repo-1"}}, nil, clock.now); err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := service.AssignEngagement(ctx, "t1", e.ID, created.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	coverage, err := service.Coverage(ctx, "t1", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(coverage.Rows) != 1 || coverage.Rows[0].Verdict != CoverageNotAssessed || coverage.Rows[0].LastAssessed != nil {
		t.Fatalf("draft coverage must be not assessed without timestamp: %+v", coverage.Rows)
	}
}

func TestCoverageVocabularyMappingAndPassing(t *testing.T) {
	mapping := map[fleetcoverage.Verdict]CoverageVerdict{
		fleetcoverage.VerdictUnauthorized: CoverageUnauthorized,
		fleetcoverage.VerdictAgentMissing: CoverageUnknown,
		fleetcoverage.VerdictRefused:      CoverageFailed,
		fleetcoverage.VerdictNever:        CoverageNotAssessed,
		fleetcoverage.VerdictStale:        CoverageStale,
		fleetcoverage.VerdictPartial:      CoveragePartial,
		fleetcoverage.VerdictCovered:      CoverageCovered,
	}
	for fleetVerdict, businessVerdict := range mapping {
		if got := MapFleetCoverageVerdict(fleetVerdict); got != businessVerdict {
			t.Errorf("map %q=%q, want %q", fleetVerdict, got, businessVerdict)
		}
	}
	for _, verdict := range []CoverageVerdict{CoverageUnauthorized, CoverageNotAssessed, CoverageExcluded, CoverageFailed, CoverageStale, CoveragePartial, CoverageUnknown} {
		if verdict.Passing() {
			t.Errorf("%q must not pass", verdict)
		}
	}
	if !CoverageCovered.Passing() {
		t.Fatal("covered must be the only passing verdict")
	}
}

func TestFindingsPreserveImportedProvenanceAndReachabilityTiers(t *testing.T) {
	service, _, engagements, findings, imported, judgments, clock := newBusinessAssetService(t)
	ctx := context.Background()
	created, err := service.Create(ctx, CreateInput{TenantID: "t1", Key: "mobile", Name: "Mobile", Type: asset.BusinessAssetApplication, Criticality: asset.CriticalityHigh, Owner: "team", Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagement.New("e1", "t1", "Login", "", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetScope([]engagement.Target{{Kind: engagement.TargetRepo, Value: "repo-1"}}, nil, clock.now); err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := service.AssignEngagement(ctx, "t1", e.ID, created.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	firstParty := finding.Finding{ID: "f1", EngagementID: e.ID, Title: "SQL injection", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindManual, DedupKey: "f1", Audit: shared.Audit{CreatedAt: clock.now, UpdatedAt: clock.now}}
	if err := findings.Upsert(ctx, []finding.Finding{firstParty}); err != nil {
		t.Fatal(err)
	}
	for index, claim := range []judgment.ReachabilityClaim{
		{Reachable: judgment.Reachable, Tier: judgment.Tier1, Confidence: 70},
		{Reachable: judgment.NotReachable, Tier: judgment.Tier2, Confidence: 95},
	} {
		row, err := judgment.New(shared.ID(fmt.Sprintf("j%d", index+1)), e.ID, judgment.CapReachability, judgment.SubjectFinding, firstParty.ID, claim, "agent", clock.now.Add(time.Duration(index)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err := judgments.Save(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	external := importedfinding.ImportedFinding{
		ID: "if1", TenantID: "t1", EngagementID: e.ID, Severity: shared.SeverityMedium,
		Title: "External result", Message: "scanner message", Suppressed: true,
		Provenance: importedfinding.Provenance{ToolName: "semgrep", ToolVersion: "1.2.3", RuleID: "rule.a", SourceDigest: "sha256:abc", IngestedBy: "alice", IngestedAt: clock.now},
		Audit:      shared.Audit{CreatedAt: clock.now, UpdatedAt: clock.now},
	}
	if _, _, err := imported.Save(ctx, "t1", []importedfinding.ImportedFinding{external}); err != nil {
		t.Fatal(err)
	}
	rows, err := service.Findings(ctx, "t1", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("findings=%d, want first-party + imported", len(rows))
	}
	var internalRow, externalRow *AggregatedFinding
	for index := range rows {
		if rows[index].External {
			externalRow = &rows[index]
		} else {
			internalRow = &rows[index]
		}
	}
	if internalRow == nil || internalRow.Reachability.State != judgment.NotReachable || internalRow.Reachability.Tier != judgment.Tier2 || len(internalRow.Reachability.History) != 2 {
		t.Fatalf("tiered reachability not preserved: %+v", internalRow)
	}
	if externalRow == nil || externalRow.Provenance == nil || externalRow.Provenance.ToolName != "semgrep" || externalRow.CanSelfPromote == nil || *externalRow.CanSelfPromote || !externalRow.SuppressedByTool {
		t.Fatalf("external governance/provenance lost: %+v", externalRow)
	}
	if externalRow.Reachability.State != judgment.ReachUnknown {
		t.Fatalf("external finding without proof must remain unknown: %+v", externalRow.Reachability)
	}
}

func TestRenameKeepsKeyMembershipsAndEngagementAssignment(t *testing.T) {
	service, _, engagements, _, _, _, clock := newBusinessAssetService(t)
	ctx := context.Background()
	created, err := service.Create(ctx, CreateInput{TenantID: "t1", Key: "mobile", Name: "Old name", Type: asset.BusinessAssetApplication, Criticality: asset.CriticalityHigh, Owner: "team", Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ReplaceProjects(ctx, "t1", created.ID, []asset.ComponentMembership{{ComponentID: "project-1", Role: asset.MembershipPrimary, Provenance: "test"}}, "alice"); err != nil {
		t.Fatal(err)
	}
	e, err := engagement.New("e-rename", "t1", "Assessment", "", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := service.AssignEngagement(ctx, "t1", e.ID, created.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	renamed, err := service.Update(ctx, "t1", created.ID, UpdateInput{Name: "New name", Description: created.Description, Type: created.Type, Criticality: created.Criticality, Owner: created.Owner, Metadata: created.Metadata, Version: created.Version, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.ID != created.ID || renamed.Key != created.Key || renamed.Name != "New name" {
		t.Fatalf("rename changed identity: before=%+v after=%+v", created, renamed)
	}
	listed, err := service.List(ctx, "t1", Filter{})
	if err != nil || len(listed) != 1 {
		t.Fatalf("rename must leave one row: rows=%+v err=%v", listed, err)
	}
	projects, err := service.Projects(ctx, "t1", created.ID)
	if err != nil || len(projects) != 1 || projects[0].ComponentID != "project-1" {
		t.Fatalf("rename lost membership: rows=%+v err=%v", projects, err)
	}
	assigned, err := service.Engagements(ctx, "t1", created.ID)
	if err != nil || len(assigned) != 1 || assigned[0].ID != e.ID {
		t.Fatalf("rename lost engagement assignment: rows=%+v err=%v", assigned, err)
	}
}
