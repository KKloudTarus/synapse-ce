package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	cmp "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Seed immutable read artifacts directly: their write-side validation is covered
// separately. This suite exercises the cross-repository list projection.
func TestCycleReadModelSelectedHeadFiltersAndFrozenClosure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	engagements := NewEngagementRepository()
	snapshots := NewAssessmentSnapshotRepository()
	comparisons := NewAssessmentComparisonRepository()
	runs := NewScanRunStore()
	repo := NewAssessmentCycleRepository(AssessmentCycleReaders{Engagements: engagements, Snapshots: snapshots, Comparisons: comparisons, Runs: runs})
	cycle, err := assessmentcycle.NewAssessmentCycle("cycle", "tenant", "Cycle", assessmentcycle.BoundaryStandalone, "", "", "root", "tester", now)
	if err != nil {
		t.Fatal(err)
	}
	cycle.SelectedHeadAssessmentID = "head"
	if err := repo.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	for index, id := range []shared.ID{"root", "head", "branch"} {
		assessment, err := engagement.New(id, "tenant", id.String(), "", now)
		if err != nil {
			t.Fatal(err)
		}
		assessment.Status = engagement.StatusCompleted
		if id == "head" {
			assessment.Status = engagement.StatusDraft
		}
		if err := engagements.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
		member, err := assessmentcycle.NewInitialMember("tenant", "cycle", id, "tester", now)
		if index > 0 {
			member, err = assessmentcycle.NewRetestMember("tenant", "cycle", id, "root", index, "tester", now)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.CreateMember(ctx, member); err != nil {
			t.Fatal(err)
		}
	}
	snapshots.byID["tenant"] = map[shared.ID]*assessmentsnapshot.Snapshot{
		"baseline": {ID: "baseline", TenantID: "tenant", AssessmentID: "root"},
		"current":  {ID: "current", TenantID: "tenant", AssessmentID: "head"},
	}
	snapshots.defaults["tenant"] = map[shared.ID]ports.AssessmentSnapshotDefault{"root": {SnapshotID: "baseline"}, "head": {SnapshotID: "current"}}
	comparison := queuedMemoryComparison(t, "tenant", "comparison", now)
	comparison.Status, comparison.CompletedAt = cmp.StatusComplete, &now
	comparison.Items = []cmp.Item{{IdentityID: "identity", ProducerKind: "sca", FindingKind: "vulnerability", Presence: cmp.PresenceDetected}}
	comparisons.comparisons[comparisonKey{"tenant", "cycle", "comparison"}] = comparison
	runs.runs[scanRunKey{"tenant", "run"}] = scanrun.ScanRun{TenantID: "tenant", EngagementID: "head", ID: "run", Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded, SealedAt: &now}
	query := ports.AssessmentCycleListQuery{TenantID: "tenant", Limit: 10, MemberLimit: 2, ScanStaleBefore: now.Add(-time.Hour)}
	rows, err := repo.ListCycles(ctx, query)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	row := rows[0]
	if row.MemberCount != 3 || !row.MembersHaveMore || row.MemberStatuses["root"] != engagement.StatusCompleted || row.MemberStatuses["head"] != engagement.StatusDraft || row.ComparisonID != "comparison" || row.ScanStaleness != "fresh" {
		t.Fatalf("projection=%+v", row)
	}
	for _, check := range []struct {
		name  string
		query ports.AssessmentCycleListQuery
		count int
	}{
		{"head draft", withCycleQuery(query, func(q *ports.AssessmentCycleListQuery) { q.AssessmentStatus = engagement.StatusDraft }), 1},
		{"completed branch is not selected head", withCycleQuery(query, func(q *ports.AssessmentCycleListQuery) { q.AssessmentStatus = engagement.StatusCompleted }), 0},
		{"producer", withCycleQuery(query, func(q *ports.AssessmentCycleListQuery) { q.ProducerKind = "sca" }), 1},
		{"wrong producer", withCycleQuery(query, func(q *ports.AssessmentCycleListQuery) { q.ProducerKind = "sast" }), 0},
		{"presence", withCycleQuery(query, func(q *ports.AssessmentCycleListQuery) { q.ChangePresence = cmp.PresenceDetected }), 1},
		{"stale", withCycleQuery(query, func(q *ports.AssessmentCycleListQuery) {
			q.ScanStaleBefore = now.Add(time.Second)
			q.ScanStaleness = "stale"
		}), 1},
		{"other tenant", withCycleQuery(query, func(q *ports.AssessmentCycleListQuery) { q.TenantID = "other" }), 0},
	} {
		t.Run(check.name, func(t *testing.T) {
			rows, err := repo.ListCycles(ctx, check.query)
			if err != nil || len(rows) != check.count {
				t.Fatalf("rows=%+v err=%v", rows, err)
			}
		})
	}
	// A closed Cycle must keep its frozen pair/comparison after defaults change.
	repo.cycles["tenant"]["cycle"].Status = assessmentcycle.StatusCompleted
	repo.cycles["tenant"]["cycle"].ActiveClosureManifestID = "manifest"
	repo.closureManifests["tenant"] = map[shared.ID]map[shared.ID]*assessmentclosure.Manifest{"cycle": {"manifest": {InitialSnapshotID: "baseline", FinalSnapshotID: "current", ComparisonID: "comparison"}}}
	snapshots.defaults["tenant"]["head"] = ports.AssessmentSnapshotDefault{SnapshotID: "replacement"}
	rows, err = repo.ListCycles(ctx, query)
	if err != nil || len(rows) != 1 || rows[0].CurrentSnapshotID != "current" || rows[0].ComparisonID != "comparison" || rows[0].ActiveManifestID != "manifest" {
		t.Fatalf("closure projection=%+v err=%v", rows, err)
	}
}

func withCycleQuery(query ports.AssessmentCycleListQuery, change func(*ports.AssessmentCycleListQuery)) ports.AssessmentCycleListQuery {
	change(&query)
	return query
}

func TestCycleMigrationPendingExcludesHiddenContextsAndPreservesBoundary(t *testing.T) {
	ctx := context.Background()
	engagements := NewEngagementRepository()
	repo := NewAssessmentCycleRepository(AssessmentCycleReaders{Engagements: engagements})
	now := time.Now().UTC()
	for _, id := range []shared.ID{"visible", "host", "hidden-project", "member", "other"} {
		tenant := shared.ID("tenant")
		if id == "other" {
			tenant = "other"
		}
		assessment, err := engagement.New(id, tenant, id.String(), "", now)
		if err != nil {
			t.Fatal(err)
		}
		switch id {
		case "visible":
			assessment.AssessmentProjectID = "project"
			assessment.BusinessAssetID = "asset"
		case "host":
			assessment.HostAssetID = "host"
		case "hidden-project":
			assessment.ProjectID = "project"
		}
		if err := engagements.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
	}
	repo.assessmentToCycle["tenant"] = map[shared.ID]shared.ID{"member": "cycle"}
	query := ports.AssessmentCycleListQuery{TenantID: "tenant", Limit: 1, BoundaryKind: assessmentcycle.BoundaryAssetProject}
	rows, total, err := repo.ListMigrationPendingAssessments(ctx, query)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].AssessmentID != "visible" || rows[0].BoundaryKind != assessmentcycle.BoundaryAssetProject {
		t.Fatalf("rows=%+v total=%d err=%v", rows, total, err)
	}
	query.BoundaryKind = assessmentcycle.BoundaryStandalone
	rows, total, err = repo.ListMigrationPendingAssessments(ctx, query)
	if err != nil || total != 1 || len(rows) != 0 {
		t.Fatalf("filtered rows=%+v total=%d err=%v", rows, total, err)
	}
}
