package assessmentcycle_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type failCompleteRequestStore struct {
	inner ports.AssessmentCycleRequestStore
	mu    sync.Mutex
	fail  bool
}

func (store *failCompleteRequestStore) failNext() {
	store.mu.Lock()
	store.fail = true
	store.mu.Unlock()
}

func (store *failCompleteRequestStore) BeginAssessmentCycleRequest(ctx context.Context, request ports.AssessmentCycleRequest) (ports.AssessmentCycleRequest, bool, error) {
	return store.inner.BeginAssessmentCycleRequest(ctx, request)
}

func (store *failCompleteRequestStore) CompleteAssessmentCycleRequest(ctx context.Context, scope ports.AssessmentCycleRequestScope, requestHash string, statusCode int, responseBody []byte, completedAt time.Time) error {
	store.mu.Lock()
	fail := store.fail
	store.fail = false
	store.mu.Unlock()
	if fail {
		return errors.New("injected retained-response failure")
	}
	return store.inner.CompleteAssessmentCycleRequest(ctx, scope, requestHash, statusCode, responseBody, completedAt)
}

func (store *failCompleteRequestStore) AbortAssessmentCycleRequest(ctx context.Context, scope ports.AssessmentCycleRequestScope, requestHash string) error {
	return store.inner.AbortAssessmentCycleRequest(ctx, scope, requestHash)
}

func TestAPIServiceRetainedLifecycle(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.ID("tenant-1")
	clock := fixedClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	ids := &seqIDGen{}
	audit := &recordAudit{}
	engagements := memory.NewEngagementRepository()
	cycles := memory.NewAssessmentCycleRepository()
	requests := memory.NewAssessmentCycleRequestRepository()
	transactions := memory.NewTenantTransactionRunner()
	engagementService := enguc.NewService(engagements, clock, ids, audit)
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	api, err := cycleuc.NewAPIService(cycleService, cycles, requests, engagementService, transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}

	createRequest := cycleuc.CreateInitialAssessmentInput{
		Request:    cycleuc.RetainedRequest{TenantID: tenantID, Actor: "alice", Route: "/api/v1/engagements", IdempotencyKey: "create-1"},
		Engagement: enguc.CreateInput{Name: "External API", Client: "Acme", InScope: []engdom.Target{{Kind: engdom.TargetDomain, Value: "api.example.com"}}},
	}
	created, err := api.CreateInitialAssessment(ctx, createRequest)
	if err != nil || created.StatusCode != 201 || created.Replayed {
		t.Fatalf("create initial response = %+v, err=%v", created, err)
	}
	var root engdom.Engagement
	if err := json.Unmarshal(created.Body, &root); err != nil {
		t.Fatal(err)
	}
	replayed, err := api.CreateInitialAssessment(ctx, createRequest)
	if err != nil || !replayed.Replayed || string(replayed.Body) != string(created.Body) {
		t.Fatalf("replay response = %+v, err=%v", replayed, err)
	}
	mismatch := createRequest
	mismatch.Engagement.Name = "Different"
	if _, err := api.CreateInitialAssessment(ctx, mismatch); !errors.Is(err, shared.ErrConflict) || cycleuc.ErrorCode(err) != cycleuc.CodeIdempotencyBodyMismatch {
		t.Fatalf("body mismatch = %v", err)
	}

	retest, err := api.CreateRetestAssessment(ctx, cycleuc.CreateRetestAssessmentInput{
		Request:      cycleuc.RetainedRequest{TenantID: tenantID, Actor: "alice", Route: "/api/v1/engagements/" + root.ID.String() + "/retests", IdempotencyKey: "retest-1"},
		AssessmentID: root.ID,
	})
	if err != nil || retest.StatusCode != 201 {
		t.Fatalf("create retest response = %+v, err=%v", retest, err)
	}
	var retestBody cycleuc.CreateRetestResponse
	if err := json.Unmarshal(retest.Body, &retestBody); err != nil {
		t.Fatal(err)
	}
	if !retestBody.Engagement.RequiresExplicitExecutionAuthorization || retestBody.Engagement.AllowsExecution() {
		t.Fatalf("Re-test execution guard missing: %+v", retestBody.Engagement)
	}
	if len(retestBody.Engagement.Scope.InScope) != 1 || retestBody.Member.RetestNumber != 1 {
		t.Fatalf("Re-test inheritance/member mismatch: %+v", retestBody)
	}

	lifecycle, err := api.GetLifecycle(ctx, tenantID, root.ID)
	if err != nil || len(lifecycle.Members) != 2 || lifecycle.Cycle.Version != 2 {
		t.Fatalf("lifecycle = %+v, err=%v", lifecycle, err)
	}
	page, err := api.ListCycles(ctx, cycleuc.ListCyclesInput{TenantID: tenantID, Limit: 1})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list cycles = %+v, err=%v", page, err)
	}
	if _, err := api.ListCycles(ctx, cycleuc.ListCyclesInput{TenantID: tenantID, Cursor: strings.Repeat("A", 685)}); cycleuc.ErrorCode(err) != cycleuc.CodeInvalidCursor {
		t.Fatalf("oversized cursor error = %v", err)
	}

	archived, err := api.ArchiveCycle(ctx, cycleuc.ArchiveCycleRequest{
		Request: cycleuc.RetainedRequest{TenantID: tenantID, Actor: "reviewer", Route: "/api/v1/assessment-cycles/" + lifecycle.Cycle.ID + "/archive", IdempotencyKey: "archive-1"},
		CycleID: shared.ID(lifecycle.Cycle.ID), ExpectedVersion: lifecycle.Cycle.Version,
	})
	if err != nil || archived.StatusCode != 200 {
		t.Fatalf("archive response = %+v, err=%v", archived, err)
	}
	detail, err := api.GetCycle(ctx, tenantID, shared.ID(lifecycle.Cycle.ID))
	if err != nil || detail.Cycle.Status != "archived" {
		t.Fatalf("archived detail = %+v, err=%v", detail, err)
	}
	apiAuditCount := 0
	for _, entry := range audit.entries {
		serialized := fmt.Sprintf("%v", entry.Metadata)
		for _, sensitive := range []string{"Acme", "api.example.com", `\"name\"`} {
			if strings.Contains(serialized, sensitive) {
				t.Fatalf("audit metadata leaked %q: %+v", sensitive, entry)
			}
		}
		if strings.HasPrefix(entry.Action, "assessment_cycle.api_") {
			apiAuditCount++
			if entry.Actor == "" || entry.Target == "" || entry.Metadata["tenant_id"] != tenantID.String() || entry.Metadata["idempotency_key"] == "" || entry.Metadata["cycle_version"] == "" {
				t.Fatalf("incomplete assessment cycle API audit entry: %+v", entry)
			}
		}
	}
	if apiAuditCount != 3 {
		t.Fatalf("assessment cycle API audit count = %d, want 3", apiAuditCount)
	}
}

func TestAPIServiceCompensatesRetainedResponseFailures(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.ID("tenant-compensation")
	clock := fixedClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	ids := &seqIDGen{}
	audit := &recordAudit{}
	engagements := memory.NewEngagementRepository()
	cycles := memory.NewAssessmentCycleRepository()
	requests := &failCompleteRequestStore{inner: memory.NewAssessmentCycleRequestRepository()}
	transactions := memory.NewTenantTransactionRunner()
	engagementService := enguc.NewService(engagements, clock, ids, audit)
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	api, err := cycleuc.NewAPIService(cycleService, cycles, requests, engagementService, transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}

	create := cycleuc.CreateInitialAssessmentInput{
		Request:    cycleuc.RetainedRequest{TenantID: tenantID, Actor: "alice", Route: "/api/v1/engagements", IdempotencyKey: "create-failure"},
		Engagement: enguc.CreateInput{Name: "Compensated", InScope: []engdom.Target{{Kind: engdom.TargetDomain, Value: "app.example.com"}}},
	}
	requests.failNext()
	if _, err := api.CreateInitialAssessment(ctx, create); err == nil {
		t.Fatal("expected retained-response failure")
	}
	assertAssessmentCycleCounts(t, ctx, engagementService, cycles, tenantID, 0, 0)

	created, err := api.CreateInitialAssessment(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	var root engdom.Engagement
	if err := json.Unmarshal(created.Body, &root); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := api.GetLifecycle(ctx, tenantID, root.ID)
	if err != nil {
		t.Fatal(err)
	}

	retest := cycleuc.CreateRetestAssessmentInput{
		Request:      cycleuc.RetainedRequest{TenantID: tenantID, Actor: "alice", Route: "/api/v1/engagements/" + root.ID.String() + "/retests", IdempotencyKey: "retest-failure"},
		AssessmentID: root.ID,
	}
	requests.failNext()
	if _, err := api.CreateRetestAssessment(ctx, retest); err == nil {
		t.Fatal("expected Re-test retained-response failure")
	}
	assertAssessmentCycleCounts(t, ctx, engagementService, cycles, tenantID, 1, 1)
	unchanged, err := api.GetLifecycle(ctx, tenantID, root.ID)
	if err != nil || unchanged.Cycle.Version != lifecycle.Cycle.Version || len(unchanged.Members) != 1 {
		t.Fatalf("Re-test compensation lifecycle = %+v, err=%v", unchanged, err)
	}
	if _, err := api.CreateRetestAssessment(ctx, retest); err != nil {
		t.Fatal(err)
	}
	lifecycle, err = api.GetLifecycle(ctx, tenantID, root.ID)
	if err != nil || len(lifecycle.Members) != 2 {
		t.Fatalf("Re-test retry lifecycle = %+v, err=%v", lifecycle, err)
	}

	archive := cycleuc.ArchiveCycleRequest{
		Request:         cycleuc.RetainedRequest{TenantID: tenantID, Actor: "reviewer", Route: "/api/v1/assessment-cycles/" + lifecycle.Cycle.ID + "/archive", IdempotencyKey: "archive-failure"},
		CycleID:         shared.ID(lifecycle.Cycle.ID),
		ExpectedVersion: lifecycle.Cycle.Version,
	}
	requests.failNext()
	if _, err := api.ArchiveCycle(ctx, archive); err == nil {
		t.Fatal("expected archive retained-response failure")
	}
	unchanged, err = api.GetLifecycle(ctx, tenantID, root.ID)
	if err != nil || unchanged.Cycle.Status != "open" || unchanged.Cycle.Version != lifecycle.Cycle.Version {
		t.Fatalf("archive compensation lifecycle = %+v, err=%v", unchanged, err)
	}
	if _, err := api.ArchiveCycle(ctx, archive); err != nil {
		t.Fatal(err)
	}
}

func TestAPIServiceListCyclesCursorAndFilterValidation(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.ID("tenant-cycle-list")
	clock := fixedClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	ids := &seqIDGen{}
	audit := &recordAudit{}
	engagements := memory.NewEngagementRepository()
	cycles := memory.NewAssessmentCycleRepository()
	transactions := memory.NewTenantTransactionRunner()
	engagementService := enguc.NewService(engagements, clock, ids, audit)
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	api, err := cycleuc.NewAPIService(cycleService, cycles, memory.NewAssessmentCycleRequestRepository(), engagementService, transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	for index, name := range []string{"Alpha", "Beta", "Gamma"} {
		_, err := api.CreateInitialAssessment(ctx, cycleuc.CreateInitialAssessmentInput{
			Request:    cycleuc.RetainedRequest{TenantID: tenantID, Actor: "alice", Route: "/api/v1/engagements", IdempotencyKey: fmt.Sprintf("list-%d", index)},
			Engagement: enguc.CreateInput{Name: name, InScope: []engdom.Target{{Kind: engdom.TargetDomain, Value: strings.ToLower(name) + ".example.com"}}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	seen := map[string]bool{}
	cursor := ""
	for {
		page, err := api.ListCycles(ctx, cycleuc.ListCyclesInput{TenantID: tenantID, Cursor: cursor, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		for _, cycle := range page.Items {
			if seen[cycle.ID] {
				t.Fatalf("duplicate cycle across cursor pages: %s", cycle.ID)
			}
			seen[cycle.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 3 {
		t.Fatalf("cursor pages returned %d cycles, want 3", len(seen))
	}
	filtered, err := api.ListCycles(ctx, cycleuc.ListCyclesInput{TenantID: tenantID, Search: " beta ", Limit: 10})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].Name != "Beta" {
		t.Fatalf("search result=%+v err=%v", filtered, err)
	}
	for name, input := range map[string]cycleuc.ListCyclesInput{
		"oversized producer": {TenantID: tenantID, ProducerKind: strings.Repeat("x", 257)},
		"control search":     {TenantID: tenantID, Search: "bad\nquery"},
		"medium change":      {TenantID: tenantID, ChangeSeverity: shared.SeverityMedium},
		"invalid staleness":  {TenantID: tenantID, ScanStaleness: "ancient"},
	} {
		if _, err := api.ListCycles(ctx, input); cycleuc.ErrorCode(err) != cycleuc.CodeInvalidFilter {
			t.Fatalf("%s error=%v code=%s", name, err, cycleuc.ErrorCode(err))
		}
	}
}

func assertAssessmentCycleCounts(t *testing.T, ctx context.Context, engagements *enguc.Service, cycles *memory.AssessmentCycleRepository, tenantID shared.ID, wantEngagements, wantCycles int) {
	t.Helper()
	items, err := engagements.List(ctx, tenantID)
	if err != nil || len(items) != wantEngagements {
		t.Fatalf("engagement count = %d, want %d, err=%v", len(items), wantEngagements, err)
	}
	records, err := cycles.ListCycles(ctx, ports.AssessmentCycleListQuery{TenantID: tenantID, Limit: 10})
	if err != nil || len(records) != wantCycles {
		t.Fatalf("cycle count = %d, want %d, err=%v", len(records), wantCycles, err)
	}
}
