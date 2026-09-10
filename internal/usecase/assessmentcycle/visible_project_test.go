package assessmentcycle_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
)

func TestVisibleProjectCycleRetestEligibilityAndOwnership(t *testing.T) {
	ctx := context.Background()
	clock := fixedClock{t: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)}
	ids := &seqIDGen{}
	engagements := memory.NewEngagementRepository()
	projects := memory.NewProjectRepository()
	for _, tenant := range []shared.ID{"tenant", "other"} {
		p, err := project.New(tenant+"-project", tenant, "Project", "project", project.SourceBinding{Kind: project.SourceGit, Value: "https://github.com/example/project"}, nil, "", clock.t)
		if err != nil {
			t.Fatal(err)
		}
		if err := projects.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	cycles := memory.NewAssessmentCycleRepository()
	tx := memory.NewTenantTransactionRunner()
	service, err := cycleuc.NewService(cycles, engagements, nil, projects, tx, ids, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	api, err := cycleuc.NewAPIService(service, cycles, memory.NewAssessmentCycleRequestRepository(), enguc.NewService(engagements, clock, ids, nil), tx, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := cycleuc.CreateInitialAssessmentInput{
		Request:    cycleuc.RetainedRequest{TenantID: "tenant", Actor: "tester", Route: "/engagements", IdempotencyKey: "visible-project"},
		Engagement: enguc.CreateInput{Name: "Visible", AssessmentProjectID: "tenant-project"},
	}
	response, err := api.CreateInitialAssessment(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	var root engdom.Engagement
	if err := json.Unmarshal(response.Body, &root); err != nil {
		t.Fatal(err)
	}
	if root.Internal() || root.AssessmentProjectID != "tenant-project" {
		t.Fatalf("visible project became hidden: %+v", root)
	}
	retest := cycleuc.CreateRetestAssessmentInput{Request: cycleuc.RetainedRequest{TenantID: "tenant", Actor: "tester", Route: "/engagements/" + root.ID.String() + "/retests", IdempotencyKey: "retest"}, AssessmentID: root.ID, PlannedDate: "2026-09-21"}
	for _, status := range []engdom.Status{engdom.StatusDraft, engdom.StatusActive, engdom.StatusArchived} {
		root.Status = status
		if err := engagements.Update(ctx, &root); err != nil {
			t.Fatal(err)
		}
		if _, err := api.CreateRetestAssessment(ctx, retest); !errors.Is(err, shared.ErrValidation) || cycleuc.ErrorCode(err) != cycleuc.CodeInvalidPredecessor {
			t.Fatalf("status %s accepted: %v", status, err)
		}
	}
	root.Status = engdom.StatusCompleted
	if err := engagements.Update(ctx, &root); err != nil {
		t.Fatal(err)
	}
	invalidDate := retest
	invalidDate.PlannedDate = "2026-02-30"
	if _, err := api.CreateRetestAssessment(ctx, invalidDate); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid planned date accepted: %v", err)
	}
	response, err = api.CreateRetestAssessment(ctx, retest)
	if err != nil {
		t.Fatal(err)
	}
	var created cycleuc.CreateRetestResponse
	if err := json.Unmarshal(response.Body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Engagement.AssessmentProjectID != root.AssessmentProjectID || created.Engagement.Internal() || created.Engagement.Status != engdom.StatusDraft || !created.Engagement.RequiresExplicitExecutionAuthorization {
		t.Fatalf("incorrect retest: %+v", created.Engagement)
	}
	if created.Member.PlannedDate != retest.PlannedDate || created.Member.AssessmentStatus != "draft" || created.Engagement.AuthorizedFrom != nil || created.Engagement.AuthorizedTo != nil || created.Engagement.AllowsExecution() {
		t.Fatalf("planned date granted execution or was lost: %+v", created)
	}
	replay, err := api.CreateRetestAssessment(ctx, retest)
	if err != nil || !replay.Replayed || string(replay.Body) != string(response.Body) {
		t.Fatalf("planning replay: %+v %v", replay, err)
	}
	changedDate := retest
	changedDate.PlannedDate = "2026-09-22"
	if _, err := api.CreateRetestAssessment(ctx, changedDate); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed date reused idempotency key: %v", err)
	}
	if created.Cycle.ProjectID != root.AssessmentProjectID.String() || created.Cycle.BoundaryKind != "project" {
		t.Fatalf("lost boundary: %+v", created.Cycle)
	}
	detail, err := api.GetLifecycle(ctx, "tenant", root.ID)
	if err != nil || len(detail.Members) != 2 || detail.Members[0].AssessmentStatus != "completed" || detail.Members[1].AssessmentStatus != "draft" || detail.Members[1].PlannedDate != retest.PlannedDate {
		t.Fatalf("member eligibility projection: %+v err=%v", detail, err)
	}
	input.Request.IdempotencyKey = "wrong-tenant-project"
	input.Engagement.AssessmentProjectID = "other-project"
	if _, err := api.CreateInitialAssessment(ctx, input); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant Project accepted: %v", err)
	}
	items, err := engagements.List(ctx, "tenant")
	if err != nil || len(items) != 2 {
		t.Fatalf("failed creation leaked engagement: %d err=%v", len(items), err)
	}
}
