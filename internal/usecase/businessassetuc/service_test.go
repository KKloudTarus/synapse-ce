package businessassetuc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
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

func TestAssignEngagementRejectsFrozenAssessmentCycleBoundary(t *testing.T) {
	service, _, engagements, _, _, _, clock := newBusinessAssetService(t)
	ctx := context.Background()
	first, err := service.Create(ctx, CreateInput{TenantID: "t1", Key: "first", Name: "First", Type: asset.BusinessAssetApplication, Criticality: asset.CriticalityHigh, Owner: "team", Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(ctx, CreateInput{TenantID: "t1", Key: "second", Name: "Second", Type: asset.BusinessAssetApplication, Criticality: asset.CriticalityHigh, Owner: "team", Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := engagement.New("assessment-frozen", "t1", "Frozen", "", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	assessment.BusinessAssetID = first.ID
	if err := engagements.Create(ctx, assessment); err != nil {
		t.Fatal(err)
	}
	cycles := memory.NewAssessmentCycleRepository()
	cycle, err := assessmentcycle.NewAssessmentCycle("cycle-frozen", "t1", "Frozen", assessmentcycle.BoundaryAsset, first.ID, "", assessment.ID, "alice", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember("t1", cycle.ID, assessment.ID, "alice", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	service.SetAssessmentCycleReader(cycles)
	if err := service.AssignEngagement(ctx, "t1", assessment.ID, second.ID, "alice"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("frozen boundary reassignment=%v", err)
	}
	stored, err := engagements.GetByIDInTenant(ctx, "t1", assessment.ID)
	if err != nil || stored.BusinessAssetID != first.ID {
		t.Fatalf("frozen boundary changed: assessment=%+v err=%v", stored, err)
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
		// A genuine Tier-2 call-graph proof: recorded entry points, full coverage, so it soundly supersedes
		// the weaker Tier-1 reachable (an UNPROVEN Tier-2 negative would not).
		{Reachable: judgment.NotReachable, Tier: judgment.Tier2, Confidence: 95, EntrypointsPresent: true},
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
	if externalRow.Finding.Kind != finding.KindExternal || externalRow.Finding.Status != finding.StatusTriage {
		t.Fatalf("external reader must be explicitly external and start in triage: %+v", externalRow.Finding)
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

// CriticalityCounts exists so a dashboard can state an estate-wide figure without listing the
// estate. It must count every Asset for the tenant, not a page of them, and it must stay scoped to
// the tenant.
func TestCriticalityCountsCoversTheWholeEstateAndOneTenant(t *testing.T) {
	service, _, _, _, _, _, _ := newBusinessAssetService(t)
	ctx := context.Background()

	// More Assets than any page the list endpoint will serve, so a page-shaped count would differ.
	for i := range 250 {
		criticality := asset.CriticalityLow
		if i%5 == 0 {
			criticality = asset.CriticalityCritical
		}
		if _, err := service.Create(ctx, CreateInput{
			TenantID: "tenant-a", Key: fmt.Sprintf("svc-a-%03d", i), Name: "Service",
			Type: asset.BusinessAssetApplication, Criticality: criticality, Owner: "platform-team", Actor: "operator",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Create(ctx, CreateInput{
		TenantID: "tenant-b", Key: "svc-b-000", Name: "Other tenant",
		Type: asset.BusinessAssetApplication, Criticality: asset.CriticalityCritical, Owner: "platform-team", Actor: "operator",
	}); err != nil {
		t.Fatal(err)
	}

	counts, err := service.CriticalityCounts(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := counts[asset.CriticalityCritical]; got != 50 {
		t.Fatalf("critical count = %d, want 50 across the whole estate", got)
	}
	if got := counts[asset.CriticalityLow]; got != 200 {
		t.Fatalf("low count = %d, want 200", got)
	}

	other, err := service.CriticalityCounts(ctx, "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	if got := other[asset.CriticalityCritical]; got != 1 {
		t.Fatalf("tenant-b critical count = %d, want 1; counts must not cross tenants", got)
	}
}

// ListPage moved filtering and pagination into the store. These assert it answers exactly what the
// previous list-everything-then-slice path answered: same matches, same order, same total.
func TestListPageMatchesTheFilterAndPagesInOrder(t *testing.T) {
	service, _, _, _, _, _, _ := newBusinessAssetService(t)
	ctx := context.Background()

	seed := func(key, name, owner string, criticality asset.Criticality, lifecycle asset.BusinessAssetLifecycle) {
		t.Helper()
		created, err := service.Create(ctx, CreateInput{
			TenantID: "tenant-a", Key: key, Name: name, Type: asset.BusinessAssetApplication,
			Criticality: criticality, Owner: owner, Actor: "operator",
		})
		if err != nil {
			t.Fatal(err)
		}
		if lifecycle != asset.BusinessAssetDraft {
			if _, err := service.Update(ctx, "tenant-a", created.ID, UpdateInput{
				Name: name, Type: asset.BusinessAssetApplication, Criticality: criticality,
				Owner: owner, Lifecycle: lifecycle, Version: created.Version, Actor: "operator",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}

	seed("api-gateway", "Edge Gateway", "platform-team", asset.CriticalityCritical, asset.BusinessAssetActive)
	seed("billing", "Billing Service", "payments-team", asset.CriticalityHigh, asset.BusinessAssetActive)
	seed("catalog", "Product Catalog", "platform-team", asset.CriticalityLow, asset.BusinessAssetDraft)
	seed("dashboard", "Ops Dashboard", "platform-team", asset.CriticalityLow, asset.BusinessAssetDraft)

	// Text matches over "<key> <name>", case-insensitively, the way the previous in-process filter did.
	items, total, err := service.ListPage(ctx, "tenant-a", Filter{Query: "PRODUCT"}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].Key != "catalog" {
		t.Fatalf("query filter returned total=%d items=%d, want the single catalog match", total, len(items))
	}

	// Owner is a case-insensitive substring too.
	if _, total, err = service.ListPage(ctx, "tenant-a", Filter{Owner: "PLATFORM"}, 10, 0); err != nil || total != 3 {
		t.Fatalf("owner filter total=%d err=%v, want 3", total, err)
	}

	// The typed filters match exactly.
	if _, total, err = service.ListPage(ctx, "tenant-a", Filter{Criticality: asset.CriticalityLow}, 10, 0); err != nil || total != 2 {
		t.Fatalf("criticality filter total=%d err=%v, want 2", total, err)
	}

	// The total is the filtered count before the page, so a page of one still reports every match.
	page, total, err := service.ListPage(ctx, "tenant-a", Filter{Owner: "platform-team"}, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want the filtered count 3 rather than the page size", total)
	}
	if len(page) != 1 || page[0].Key != "api-gateway" {
		t.Fatalf("first page = %v, want api-gateway first by key order", page)
	}

	// Paging walks the same key order without repeating or skipping a row.
	seen := []string{}
	for offset := 0; offset < total; offset++ {
		rows, _, err := service.ListPage(ctx, "tenant-a", Filter{Owner: "platform-team"}, 1, offset)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("offset %d returned %d rows, want 1", offset, len(rows))
		}
		seen = append(seen, rows[0].Key)
	}
	if strings.Join(seen, ",") != "api-gateway,catalog,dashboard" {
		t.Fatalf("paged order = %v, want key order with no gap or repeat", seen)
	}

	// An offset past the end is an empty page, not an error, and the total still holds.
	rows, total, err := service.ListPage(ctx, "tenant-a", Filter{}, 10, 99)
	if err != nil || len(rows) != 0 || total != 4 {
		t.Fatalf("offset past end: rows=%d total=%d err=%v, want 0 rows and total 4", len(rows), total, err)
	}
}
