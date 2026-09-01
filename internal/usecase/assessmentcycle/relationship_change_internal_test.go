package assessmentcycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	cmpuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type relationshipClock struct{ now time.Time }

func (clock relationshipClock) Now() time.Time { return clock.now }

type relationshipIDs struct{ next int }

func (ids *relationshipIDs) NewID() shared.ID {
	ids.next++
	return shared.ID(fmt.Sprintf("relationship-id-%d", ids.next))
}

type relationshipAudit struct{ entries []ports.AuditEntry }

func (audit *relationshipAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	audit.entries = append(audit.entries, entry)
	return nil
}

type failingRelationshipRequestStore struct {
	*memory.AssessmentCycleRequestRepository
}

func (store failingRelationshipRequestStore) CompleteAssessmentCycleRequest(context.Context, ports.AssessmentCycleRequestScope, string, int, []byte, time.Time) error {
	return errors.New("injected retained response failure")
}

func TestRelationshipPreviewCommitAndReplaySafety(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.ID("tenant-relationship")
	clock := relationshipClock{now: time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)}
	ids, audit := &relationshipIDs{}, &relationshipAudit{}
	cycles := memory.NewAssessmentCycleRepository()
	transactions := memory.NewTenantTransactionRunner()
	engagements := memory.NewEngagementRepository()
	requests := memory.NewAssessmentCycleRequestRepository()
	snapshots := memory.NewAssessmentSnapshotRepository()
	comparisons := memory.NewAssessmentComparisonRepository()
	lineage := memory.NewFindingLineageRepository()
	scanJobs := memory.NewScanJobStore()

	cycle, err := cycledom.NewAssessmentCycle("cycle-relationship", tenantID, "Relationship cycle", cycledom.BoundaryStandalone, "", "", "root", "alice", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest("head-a", "root", cycle.Version, "alice", clock.now); err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest("head-b", "root", cycle.Version, "alice", clock.now); err != nil {
		t.Fatal(err)
	}
	root, _ := cycledom.NewInitialMember(tenantID, cycle.ID, "root", "alice", clock.now)
	headA, _ := cycledom.NewRetestMember(tenantID, cycle.ID, "head-a", "root", 1, "alice", clock.now)
	headB, _ := cycledom.NewRetestMember(tenantID, cycle.ID, "head-b", "root", 2, "alice", clock.now)
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	for _, member := range []*cycledom.Member{root, headA, headB} {
		if err := cycles.CreateMember(ctx, member); err != nil {
			t.Fatal(err)
		}
	}
	cycleService, err := NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewAPIService(cycleService, cycles, requests, enguc.NewService(engagements, clock, ids, audit), transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	comparisonService, err := cmpuc.NewService(comparisons, snapshots, cycles, lineage, transactions, audit, clock, ids, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.SetRelationshipChangeDependencies(snapshots, comparisons, lineage, scanJobs, comparisonService, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}

	change := RelationshipChangeRequest{Command: RelationshipCommandSelectHead, SelectedHeadAssessmentID: headB.AssessmentID}
	preview, err := api.PreviewRelationshipChange(ctx, RelationshipPreviewInput{TenantID: tenantID, Actor: "reviewer", CycleID: cycle.ID, Request: change})
	if err != nil || !preview.CommitAllowed || preview.PreviewToken == "" || preview.NewSelectedHeadAssessmentID != headB.AssessmentID.String() {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
	commit := RelationshipCommitInput{
		Request: RetainedRequest{TenantID: tenantID, Actor: "reviewer", Route: "/api/v1/assessment-cycles/cycle-relationship/relationship-commits", IdempotencyKey: "relationship-commit-1"},
		CycleID: cycle.ID, Change: change, PreviewToken: preview.PreviewToken, ExpectedVersion: preview.CycleVersion,
	}
	response, err := api.CommitRelationshipChange(ctx, commit)
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("commit=%+v err=%v", response, err)
	}
	var result RelationshipCommitResult
	if err := json.Unmarshal(response.Body, &result); err != nil || result.Cycle.SelectedHeadAssessmentID != headB.AssessmentID.String() {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	replay, err := api.CommitRelationshipChange(ctx, commit)
	if err != nil || !replay.Replayed || string(replay.Body) != string(response.Body) {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	commit.Request.IdempotencyKey = "relationship-commit-2"
	if _, err := api.CommitRelationshipChange(ctx, commit); !errors.Is(err, shared.ErrConflict) || ErrorCode(err) != CodeRelationshipPreviewStale {
		t.Fatalf("reused preview error=%v code=%s", err, ErrorCode(err))
	}
	tampered := preview.PreviewToken[:len(preview.PreviewToken)-1] + "x"
	commit.PreviewToken, commit.Request.IdempotencyKey = tampered, "relationship-commit-3"
	if _, err := api.CommitRelationshipChange(ctx, commit); err == nil || ErrorCode(err) != CodeRelationshipPreviewInvalid {
		t.Fatalf("tampered preview error=%v code=%s", err, ErrorCode(err))
	}
}

func TestRelationshipCommitCompensatesGraphWhenRetainedResponseFails(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.ID("tenant-relationship-compensation")
	clock := relationshipClock{now: time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)}
	ids, audit := &relationshipIDs{}, &relationshipAudit{}
	cycles := memory.NewAssessmentCycleRepository()
	transactions := memory.NewTenantTransactionRunner()
	engagements := memory.NewEngagementRepository()
	snapshots := memory.NewAssessmentSnapshotRepository()
	comparisons := memory.NewAssessmentComparisonRepository()
	lineage := memory.NewFindingLineageRepository()
	scanJobs := memory.NewScanJobStore()

	cycle, err := cycledom.NewAssessmentCycle("cycle-compensation", tenantID, "Compensation cycle", cycledom.BoundaryStandalone, "", "", "root", "alice", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest("head-a", "root", cycle.Version, "alice", clock.now); err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest("head-b", "root", cycle.Version, "alice", clock.now); err != nil {
		t.Fatal(err)
	}
	root, _ := cycledom.NewInitialMember(tenantID, cycle.ID, "root", "alice", clock.now)
	headA, _ := cycledom.NewRetestMember(tenantID, cycle.ID, "head-a", "root", 1, "alice", clock.now)
	headB, _ := cycledom.NewRetestMember(tenantID, cycle.ID, "head-b", "root", 2, "alice", clock.now)
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	for _, member := range []*cycledom.Member{root, headA, headB} {
		if err := cycles.CreateMember(ctx, member); err != nil {
			t.Fatal(err)
		}
	}
	cycleService, err := NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	requestStore := failingRelationshipRequestStore{AssessmentCycleRequestRepository: memory.NewAssessmentCycleRequestRepository()}
	api, err := NewAPIService(cycleService, cycles, requestStore, enguc.NewService(engagements, clock, ids, audit), transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	comparisonService, err := cmpuc.NewService(comparisons, snapshots, cycles, lineage, transactions, audit, clock, ids, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.SetRelationshipChangeDependencies(snapshots, comparisons, lineage, scanJobs, comparisonService, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}

	change := RelationshipChangeRequest{Command: RelationshipCommandSelectHead, SelectedHeadAssessmentID: headB.AssessmentID}
	preview, err := api.PreviewRelationshipChange(ctx, RelationshipPreviewInput{TenantID: tenantID, Actor: "reviewer", CycleID: cycle.ID, Request: change})
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.CommitRelationshipChange(ctx, RelationshipCommitInput{
		Request: RetainedRequest{TenantID: tenantID, Actor: "reviewer", Route: "/api/v1/assessment-cycles/cycle-compensation/relationship-commits", IdempotencyKey: "compensate-1"},
		CycleID: cycle.ID, Change: change, PreviewToken: preview.PreviewToken, ExpectedVersion: preview.CycleVersion,
	})
	if err == nil || !strings.Contains(err.Error(), "injected retained response failure") {
		t.Fatalf("commit error=%v", err)
	}
	stored, err := cycles.GetCycle(ctx, tenantID, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SelectedHeadAssessmentID != headA.AssessmentID || stored.Version != preview.CycleVersion {
		t.Fatalf("graph was not compensated: %+v", stored)
	}
}
