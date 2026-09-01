package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	engagementuc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type failingPostgresRelationshipRequestStore struct {
	*AssessmentCycleRequestRepository
}

func (store failingPostgresRelationshipRequestStore) CompleteAssessmentCycleRequest(context.Context, ports.AssessmentCycleRequestScope, string, int, []byte, time.Time) error {
	return errors.New("injected postgres retained response failure")
}

func TestPostgresAssessmentRelationshipChangeConcurrencyRLSAndRollback(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("relationship-change-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	otherTenantID := shared.ID("other-" + suffix)
	cycleID := shared.ID("cycle-" + suffix)
	rootID := shared.ID("root-" + suffix)
	headAID := shared.ID("head-a-" + suffix)
	headBID := shared.ID("head-b-" + suffix)
	for _, tenant := range []shared.ID{tenantID, otherTenantID} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name) VALUES($1,$2) ON CONFLICT (id) DO NOTHING`, tenant.String(), tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, assessmentID := range []shared.ID{rootID, headAID, headBID} {
		ensureTestTenantAndEngagement(t, ctx, pool, tenantID, assessmentID, "", "")
	}

	cycles := NewAssessmentCycleRepository(pool)
	engagements := NewEngagementRepository(pool)
	transactions := NewTenantTransactionRunner(pool)
	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}
	audit := assessmentCycleNoopAudit{}
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	engagementService := engagementuc.NewService(engagements, clock, ids, audit)
	requestStore := NewAssessmentCycleRequestRepository(pool)
	api, err := cycleuc.NewAPIService(cycleService, cycles, requestStore, engagementService, transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := NewAssessmentSnapshotRepository(pool)
	comparisons := NewAssessmentComparisonRepository(pool)
	lineage := NewFindingLineageRepository(pool)
	comparisonService, err := comparisonuc.NewService(comparisons, snapshots, cycles, lineage, transactions, audit, clock, ids, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.SetRelationshipChangeDependencies(snapshots, comparisons, lineage, NewScanJobStore(pool), comparisonService, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	cycle, err := cycledom.NewAssessmentCycle(cycleID, tenantID, "Relationship change", cycledom.BoundaryStandalone, "", "", rootID, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest(headAID, rootID, cycle.Version, "operator", now); err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest(headBID, rootID, cycle.Version, "operator", now); err != nil {
		t.Fatal(err)
	}
	root, _ := cycledom.NewInitialMember(tenantID, cycleID, rootID, "operator", now)
	headA, _ := cycledom.NewRetestMember(tenantID, cycleID, headAID, rootID, 1, "operator", now)
	headB, _ := cycledom.NewRetestMember(tenantID, cycleID, headBID, rootID, 2, "operator", now)
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	for _, member := range []*cycledom.Member{root, headA, headB} {
		if err := cycles.CreateMember(ctx, member); err != nil {
			t.Fatal(err)
		}
	}
	change := cycleuc.RelationshipChangeRequest{Command: cycleuc.RelationshipCommandSelectHead, SelectedHeadAssessmentID: headBID}
	if _, err := api.PreviewRelationshipChange(ctx, cycleuc.RelationshipPreviewInput{TenantID: otherTenantID, Actor: "reviewer", CycleID: cycleID, Request: change}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant preview error=%v", err)
	}
	previews := make([]cycleuc.RelationshipPreview, 2)
	for index := range previews {
		previews[index], err = api.PreviewRelationshipChange(ctx, cycleuc.RelationshipPreviewInput{TenantID: tenantID, Actor: "reviewer", CycleID: cycleID, Request: change})
		if err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	errorsCh := make(chan error, len(previews))
	var wait sync.WaitGroup
	for index, preview := range previews {
		wait.Add(1)
		go func(index int, preview cycleuc.RelationshipPreview) {
			defer wait.Done()
			<-start
			_, commitErr := api.CommitRelationshipChange(ctx, cycleuc.RelationshipCommitInput{
				Request: cycleuc.RetainedRequest{TenantID: tenantID, Actor: "reviewer", Route: "/api/v1/assessment-cycles/" + cycleID.String() + "/relationship-commits", IdempotencyKey: fmt.Sprintf("concurrent-%d", index)},
				CycleID: cycleID, Change: change, PreviewToken: preview.PreviewToken, ExpectedVersion: preview.CycleVersion,
			})
			errorsCh <- commitErr
		}(index, preview)
	}
	close(start)
	wait.Wait()
	close(errorsCh)
	succeeded, conflicted := 0, 0
	for commitErr := range errorsCh {
		switch {
		case commitErr == nil:
			succeeded++
		case errors.Is(commitErr, shared.ErrConflict) && cycleuc.ErrorCode(commitErr) == cycleuc.CodeRelationshipPreviewStale:
			conflicted++
		default:
			t.Fatalf("unexpected concurrent commit error=%v", commitErr)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent outcomes succeeded=%d conflicted=%d", succeeded, conflicted)
	}
	stored, err := cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil || stored.SelectedHeadAssessmentID != headBID || stored.Version != previews[0].CycleVersion+1 {
		t.Fatalf("stored cycle=%+v err=%v", stored, err)
	}

	failingAPI, err := cycleuc.NewAPIService(cycleService, cycles, failingPostgresRelationshipRequestStore{AssessmentCycleRequestRepository: requestStore}, engagementService, transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	if err := failingAPI.SetRelationshipChangeDependencies(snapshots, comparisons, lineage, NewScanJobStore(pool), comparisonService, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	rollbackChange := cycleuc.RelationshipChangeRequest{Command: cycleuc.RelationshipCommandSelectHead, SelectedHeadAssessmentID: headAID}
	rollbackPreview, err := failingAPI.PreviewRelationshipChange(ctx, cycleuc.RelationshipPreviewInput{TenantID: tenantID, Actor: "reviewer", CycleID: cycleID, Request: rollbackChange})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingAPI.CommitRelationshipChange(ctx, cycleuc.RelationshipCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: tenantID, Actor: "reviewer", Route: "/api/v1/assessment-cycles/" + cycleID.String() + "/relationship-commits", IdempotencyKey: "rollback"},
		CycleID: cycleID, Change: rollbackChange, PreviewToken: rollbackPreview.PreviewToken, ExpectedVersion: rollbackPreview.CycleVersion,
	}); err == nil || !strings.Contains(err.Error(), "injected postgres retained response failure") {
		t.Fatalf("rollback commit error=%v", err)
	}
	afterRollback, err := cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil || afterRollback.SelectedHeadAssessmentID != headBID || afterRollback.Version != stored.Version {
		t.Fatalf("rollback left mutation: cycle=%+v err=%v", afterRollback, err)
	}
}
