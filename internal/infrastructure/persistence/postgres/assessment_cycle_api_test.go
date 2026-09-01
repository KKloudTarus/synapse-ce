package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type assessmentCycleNoopAudit struct{}

func (assessmentCycleNoopAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func TestPostgresAssessmentCycleAPIReplayConcurrency(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("cycle-api-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	otherTenantID := shared.ID("other-" + suffix)
	for _, tenant := range []shared.ID{tenantID, otherTenantID} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$2)`, tenant.String(), tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	engagements := NewEngagementRepository(pool)
	cycles := NewAssessmentCycleRepository(pool)
	transactions := NewTenantTransactionRunner(pool)
	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}
	audit := assessmentCycleNoopAudit{}
	engagementService := enguc.NewService(engagements, clock, ids, audit)
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	api, err := cycleuc.NewAPIService(cycleService, cycles, NewAssessmentCycleRequestRepository(pool), engagementService, transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	input := cycleuc.CreateInitialAssessmentInput{
		Request:    cycleuc.RetainedRequest{TenantID: tenantID, Actor: "alice", Route: "/api/v1/engagements", IdempotencyKey: "same-key"},
		Engagement: enguc.CreateInput{Name: "Concurrent", InScope: []engdom.Target{{Kind: engdom.TargetDomain, Value: "app.example.com"}}},
	}

	const callers = 8
	responses := make(chan cycleuc.RetainedResponse, callers)
	errorsCh := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, err := api.CreateInitialAssessment(ctx, input)
			responses <- response
			errorsCh <- err
		}()
	}
	wait.Wait()
	close(responses)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent create: %v", err)
		}
	}
	var body string
	for response := range responses {
		if response.StatusCode != 201 {
			t.Fatalf("status=%d", response.StatusCode)
		}
		if body == "" {
			body = string(response.Body)
		} else if string(response.Body) != body {
			t.Fatalf("retained bodies differ: %q != %q", response.Body, body)
		}
	}
	var engagementCount, cycleCount, requestCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM engagements WHERE tenant_id=$1`, tenantID.String()).Scan(&engagementCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM assessment_cycles WHERE tenant_id=$1`, tenantID.String()).Scan(&cycleCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM assessment_cycle_api_requests WHERE tenant_id=$1`, tenantID.String()).Scan(&requestCount); err != nil {
		t.Fatal(err)
	}
	if engagementCount != 1 || cycleCount != 1 || requestCount != 1 {
		t.Fatalf("counts engagement=%d cycle=%d request=%d", engagementCount, cycleCount, requestCount)
	}

	mismatch := input
	mismatch.Engagement.Name = "Mismatch"
	if _, err := api.CreateInitialAssessment(ctx, mismatch); !errors.Is(err, shared.ErrConflict) || cycleuc.ErrorCode(err) != cycleuc.CodeIdempotencyBodyMismatch {
		t.Fatalf("body mismatch=%v", err)
	}
	engagementList, err := engagementService.List(ctx, tenantID)
	if err != nil || len(engagementList) != 1 {
		t.Fatalf("engagement list=%d err=%v", len(engagementList), err)
	}
	retest, err := api.CreateRetestAssessment(ctx, cycleuc.CreateRetestAssessmentInput{
		Request:      cycleuc.RetainedRequest{TenantID: tenantID, Actor: "alice", Route: "/api/v1/engagements/" + engagementList[0].ID.String() + "/retests", IdempotencyKey: "retest-key"},
		AssessmentID: engagementList[0].ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	var retestBody cycleuc.CreateRetestResponse
	if err := json.Unmarshal(retest.Body, &retestBody); err != nil {
		t.Fatal(err)
	}
	persistedRetest, err := engagementService.Get(ctx, tenantID, retestBody.Engagement.ID)
	if err != nil || !persistedRetest.RequiresExplicitExecutionAuthorization || persistedRetest.AllowsExecution() {
		t.Fatalf("persisted Re-test=%+v err=%v", persistedRetest, err)
	}
	if _, err := api.GetLifecycle(ctx, otherTenantID, engagementList[0].ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant lifecycle=%v", err)
	}
}

func TestPostgresAssessmentCycleListProjectionFilters(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("cycle-list-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	freshAssessmentID := shared.ID("fresh-assessment-" + suffix)
	missingAssessmentID := shared.ID("missing-assessment-" + suffix)
	for _, assessmentID := range []shared.ID{freshAssessmentID, missingAssessmentID} {
		ensureTestTenantAndEngagement(t, ctx, pool, tenantID, assessmentID, "", "")
		if _, err := pool.Exec(ctx, `UPDATE engagements SET status='active' WHERE tenant_id=$1 AND id=$2`, tenantID.String(), assessmentID.String()); err != nil {
			t.Fatal(err)
		}
	}
	repository := NewAssessmentCycleRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, fixture := range []struct {
		id           shared.ID
		name         string
		assessmentID shared.ID
	}{
		{id: shared.ID("fresh-cycle-" + suffix), name: "Fresh Cycle", assessmentID: freshAssessmentID},
		{id: shared.ID("missing-cycle-" + suffix), name: "Missing Cycle", assessmentID: missingAssessmentID},
	} {
		cycle, err := cycledom.NewAssessmentCycle(fixture.id, tenantID, fixture.name, cycledom.BoundaryStandalone, "", "", fixture.assessmentID, "alice", now)
		if err != nil {
			t.Fatal(err)
		}
		member, err := cycledom.NewInitialMember(tenantID, fixture.id, fixture.assessmentID, "alice", now)
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.CreateCycle(ctx, cycle); err != nil {
			t.Fatal(err)
		}
		if err := repository.CreateMember(ctx, member); err != nil {
			t.Fatal(err)
		}
	}
	run := postgresNativeRun(t, tenantID, freshAssessmentID, shared.ID("fresh-run-"+suffix), strings.Repeat("a", 64))
	runRepository := NewScanRunStore(pool)
	if err := runRepository.Begin(ctx, beginningPostgresScanRun(run)); err != nil {
		t.Fatal(err)
	}
	if err := run.Seal(scanrun.StatusSucceeded, 1, now); err != nil {
		t.Fatal(err)
	}
	if err := runRepository.Seal(ctx, run); err != nil {
		t.Fatal(err)
	}

	records, err := repository.ListCycles(ctx, ports.AssessmentCycleListQuery{
		TenantID: tenantID, AssessmentStatus: engdom.StatusActive, SelectedHeadID: freshAssessmentID,
		AssessmentType: cycledom.AssessmentTypeInitial, ScanStaleness: "fresh", ScanStaleBefore: now.Add(-24 * time.Hour), Search: "Fresh", Limit: 10, MemberLimit: 10,
	})
	if err != nil || len(records) != 1 || records[0].Cycle.Name != "Fresh Cycle" || records[0].ScanStaleness != "fresh" || records[0].SelectedHeadScanAt == nil {
		t.Fatalf("fresh projection=%+v err=%v", records, err)
	}
	for name, filter := range map[string]ports.AssessmentCycleListQuery{
		"missing":  {TenantID: tenantID, ScanStaleness: "missing", ScanStaleBefore: now.Add(-24 * time.Hour), Limit: 10, MemberLimit: 10},
		"producer": {TenantID: tenantID, ProducerKind: "absent-producer", ScanStaleBefore: now.Add(-24 * time.Hour), Limit: 10, MemberLimit: 10},
		"review":   {TenantID: tenantID, ReviewState: "needs_review", ScanStaleBefore: now.Add(-24 * time.Hour), Limit: 10, MemberLimit: 10},
	} {
		filtered, err := repository.ListCycles(ctx, filter)
		if err != nil {
			t.Fatalf("%s filter: %v", name, err)
		}
		if name == "missing" && (len(filtered) != 1 || filtered[0].Cycle.Name != "Missing Cycle") {
			t.Fatalf("missing filter=%+v", filtered)
		}
		if name != "missing" && len(filtered) != 0 {
			t.Fatalf("%s filter unexpectedly returned %+v", name, filtered)
		}
	}
}
