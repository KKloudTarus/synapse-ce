package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type closureRoundTripReferences struct{}

func (closureRoundTripReferences) ListAssessmentClosureReferences(context.Context, shared.ID, ports.AssessmentClosureReferenceQuery) ([]assessmentclosure.Reference, error) {
	return nil, nil
}
func (closureRoundTripReferences) ResolveAssessmentClosureReference(context.Context, shared.ID, ports.AssessmentClosureReferenceQuery, assessmentclosure.Reference) error {
	return nil
}

// Exercise the repository and real report renderer, not SQL-only migration
// fixtures: empty lists and JSONB object ordering must preserve domain hashes.
func TestPostgresAssessmentClosureRoundTripReportAndReopen(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("closure-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	cycleID, baseline, current := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	comparisons, cycles := NewAssessmentComparisonRepository(pool), NewAssessmentCycleRepository(pool)
	comparison := postgresQueuedComparison(t, tenantID, cycleID, shared.ID("comparison-"+suffix), baseline, current, 1, now)
	if _, _, err := comparisons.CreateQueued(ctx, comparison); err != nil {
		t.Fatal(err)
	}
	if err := comparison.Start(1, now); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 1); err != nil {
		t.Fatal(err)
	}
	if err := comparison.Complete(nil, 2, now); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 2); err != nil {
		t.Fatal(err)
	}
	cycle, err := cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil {
		t.Fatal(err)
	}
	version := cycle.Version
	manifest, err := assessmentclosure.NewManifest(shared.ID("manifest-"+suffix), assessmentclosure.ManifestInput{
		TenantID: tenantID, CycleID: cycleID, ManifestVersion: 1, CycleVersion: version + 1,
		RootAssessmentID: baseline.AssessmentID, FinalAssessmentID: current.AssessmentID,
		InitialSnapshot: baseline, FinalSnapshot: current, Comparison: &comparison,
		Path:       []assessmentclosure.PathMember{{PathPosition: 0, AssessmentID: baseline.AssessmentID, AssessmentType: assessmentcycle.AssessmentTypeInitial, RelationshipVersion: 1, SnapshotID: current.ID}},
		References: []assessmentclosure.Reference{{Kind: "test_reference", ID: "reference", Version: 1, Metadata: json.RawMessage(`{"zz":1,"a_long_key":9007199254740993}`)}},
		Reason:     "round trip", AsOfAt: now, CreatedAt: now, CreatedBy: "reviewer",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Seal(now, "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := cycle.CompleteWithManifest(manifest.ID, version, "reviewer", now); err != nil {
		t.Fatal(err)
	}
	commit := ports.AssessmentClosureCommit{Cycle: cycle, Manifest: manifest, ExpectedCycleVersion: version}
	if err := cycles.CommitClosure(ctx, commit); err != nil {
		t.Fatalf("commit empty lists: %v", err)
	}
	loaded, err := cycles.GetClosureManifest(ctx, tenantID, cycleID, manifest.ID)
	if err != nil || loaded.ContentHash != manifest.ContentHash || !bytes.Equal(loaded.References[0].Metadata, manifest.References[0].Metadata) {
		t.Fatalf("JSONB round trip: %+v err=%v", loaded, err)
	}
	if err := cycles.CommitClosure(ctx, commit); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale commit: %v", err)
	}
	if _, err := cycles.GetClosureManifest(ctx, "other-tenant", cycleID, manifest.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	reports, err := cycleuc.NewClosureReportService(cycles, cycles, NewAssessmentSnapshotRepository(pool), comparisons, closureRoundTripReferences{}, assessmentCycleNoopAudit{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := reports.Render(ctx, tenantID, cycleID, manifest.ID)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	version = cycle.Version
	if err := cycle.ReopenFromManifest(version, "reviewer", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Supersede(now.Add(time.Minute), ""); err != nil {
		t.Fatal(err)
	}
	if err := cycles.ReopenClosure(ctx, ports.AssessmentClosureReopen{Cycle: cycle, Manifest: loaded, ExpectedCycleVersion: version}); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	history, err := cycles.ListClosureManifests(ctx, tenantID, cycleID)
	if err != nil || len(history) != 1 || history[0].Lifecycle != assessmentclosure.LifecycleSuperseded || history[0].ContentHash != manifest.ContentHash {
		t.Fatalf("history: %+v err=%v", history, err)
	}
	retained, err := reports.Render(ctx, tenantID, cycleID, manifest.ID)
	if err != nil || retained.ContentHash != report.ContentHash || !bytes.Equal(retained.Content, report.Content) {
		t.Fatalf("report changed after reopen: err=%v", err)
	}
}
