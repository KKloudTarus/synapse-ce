package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type assessmentCycleHTTPIDs struct{ next int }

func (ids *assessmentCycleHTTPIDs) NewID() shared.ID {
	ids.next++
	return shared.ID("cycle-http-" + strconv.Itoa(ids.next))
}

type assessmentCycleHTTPObserver struct{ outcomes []string }

func (*assessmentCycleHTTPObserver) ObserveHTTPRequest(string, string, string, time.Duration) {}

func (observer *assessmentCycleHTTPObserver) ObserveAssessmentCycleDualWrite(outcome string) {
	observer.outcomes = append(observer.outcomes, outcome)
}

func (observer *assessmentCycleHTTPObserver) count(outcome string) int {
	count := 0
	for _, observed := range observer.outcomes {
		if observed == outcome {
			count++
		}
	}
	return count
}

func newAssessmentCycleHTTPRouter(t *testing.T, apiEnabled bool, dualWrite func(string) bool) (*Router, *memory.AssessmentCycleRepository, *assessmentCycleHTTPObserver) {
	t.Helper()
	clock := fixedClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	ids := &assessmentCycleHTTPIDs{}
	audit := &fakeAudit{}
	engagements := memory.NewEngagementRepository()
	cycles := memory.NewAssessmentCycleRepository()
	transactions := memory.NewTenantTransactionRunner()
	engagementService := enguc.NewService(engagements, clock, ids, audit)
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	cycleAPI, err := cycleuc.NewAPIService(cycleService, cycles, memory.NewAssessmentCycleRequestRepository(), engagementService, transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := memory.NewAssessmentSnapshotRepository()
	comparisons := memory.NewAssessmentComparisonRepository()
	lineage := memory.NewFindingLineageRepository()
	verification, err := comparisonuc.NewRetestVerificationReader(lineage, snapshots, memory.NewRetestRepository())
	if err != nil {
		t.Fatal(err)
	}
	comparisonService, err := comparisonuc.NewService(comparisons, snapshots, cycles, lineage, transactions, audit, clock, ids, verification, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cycleAPI.SetRelationshipChangeDependencies(snapshots, comparisons, lineage, memory.NewScanJobStore(), comparisonService, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	observer := &assessmentCycleHTTPObserver{}
	router := &Router{log: discardLog(), eng: engagementService}
	router.SetObservability(false, observer)
	router.SetAssessmentCycles(cycleAPI, apiEnabled, dualWrite)
	return router, cycles, observer
}

func TestAssessmentLifecycleReadGateIsTenantScopedAndFailClosed(t *testing.T) {
	router, _, _ := newAssessmentCycleHTTPRouter(t, true, func(string) bool { return true })
	router.SetAssessmentLifecycleRollout(func(tenantID string) bool { return tenantID == "tenant-canary" }, func(string) bool { return false })
	handler := router.requireAssessmentLifecycleRead(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	blocked := httptest.NewRecorder()
	handler(blocked, cycleRequest(http.MethodGet, "/api/v1/assessment-cycles", "", userdom.RoleReadOnly, "tenant-other"))
	if blocked.Code != http.StatusNotFound || !strings.Contains(blocked.Body.String(), "assessment_lifecycle_read_disabled") {
		t.Fatalf("blocked lifecycle read = %d %s", blocked.Code, blocked.Body.String())
	}

	allowed := httptest.NewRecorder()
	handler(allowed, cycleRequest(http.MethodGet, "/api/v1/assessment-cycles", "", userdom.RoleReadOnly, "tenant-canary"))
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("allowed lifecycle read = %d", allowed.Code)
	}
}

func TestAssessmentRelationshipChangeHTTPContract(t *testing.T) {
	router, cycles, _ := newAssessmentCycleHTTPRouter(t, true, func(string) bool { return true })
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tenantID := shared.ID("tenant-relationship-http")
	cycle, err := cycledom.NewAssessmentCycle("cycle-relationship-http", tenantID, "Relationship HTTP", cycledom.BoundaryStandalone, "", "", "root", "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest("head-a", "root", cycle.Version, "operator", now); err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest("head-b", "root", cycle.Version, "operator", now); err != nil {
		t.Fatal(err)
	}
	root, _ := cycledom.NewInitialMember(tenantID, cycle.ID, "root", "operator", now)
	headA, _ := cycledom.NewRetestMember(tenantID, cycle.ID, "head-a", "root", 1, "operator", now)
	headB, _ := cycledom.NewRetestMember(tenantID, cycle.ID, "head-b", "root", 2, "operator", now)
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	for _, member := range []*cycledom.Member{root, headA, headB} {
		if err := cycles.CreateMember(ctx, member); err != nil {
			t.Fatal(err)
		}
	}
	handler := router.routes()
	path := "/api/v1/assessment-cycles/" + cycle.ID.String()
	changeBody := `{"command":"select_head","selected_head_assessment_id":"head-b"}`

	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, cycleRequest(http.MethodPost, path+"/relationship-previews", changeBody, userdom.RoleReadOnly, tenantID.String()))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("permission response=%d body=%s", denied.Code, denied.Body.String())
	}
	crossTenant := httptest.NewRecorder()
	handler.ServeHTTP(crossTenant, cycleRequest(http.MethodPost, path+"/relationship-previews", changeBody, userdom.RoleReviewer, "other-tenant"))
	if crossTenant.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant response=%d body=%s", crossTenant.Code, crossTenant.Body.String())
	}

	previewResponse := httptest.NewRecorder()
	handler.ServeHTTP(previewResponse, cycleRequest(http.MethodPost, path+"/relationship-previews", changeBody, userdom.RoleReviewer, tenantID.String()))
	if previewResponse.Code != http.StatusOK {
		t.Fatalf("preview response=%d body=%s", previewResponse.Code, previewResponse.Body.String())
	}
	var preview cycleuc.RelationshipPreview
	if err := json.Unmarshal(previewResponse.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if !preview.CommitAllowed || preview.PreviewToken == "" || preview.NewSelectedHeadAssessmentID != "head-b" {
		t.Fatalf("preview=%+v", preview)
	}
	commitBody := `{"command":"select_head","selected_head_assessment_id":"head-b","preview_token":"` + preview.PreviewToken + `"}`
	missingPrecondition := httptest.NewRecorder()
	handler.ServeHTTP(missingPrecondition, cycleRequest(http.MethodPost, path+"/relationship-commits", commitBody, userdom.RoleReviewer, tenantID.String()))
	if missingPrecondition.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match response=%d body=%s", missingPrecondition.Code, missingPrecondition.Body.String())
	}

	commitRequest := cycleRequest(http.MethodPost, path+"/relationship-commits", commitBody, userdom.RoleReviewer, tenantID.String())
	commitRequest.Header.Set("If-Match", strconv.FormatInt(preview.CycleVersion, 10))
	commitRequest.Header.Set("Idempotency-Key", "relationship-http-commit")
	committed := httptest.NewRecorder()
	handler.ServeHTTP(committed, commitRequest)
	if committed.Code != http.StatusOK {
		t.Fatalf("commit response=%d body=%s", committed.Code, committed.Body.String())
	}

	replayRequest := cycleRequest(http.MethodPost, path+"/relationship-commits", commitBody, userdom.RoleReviewer, tenantID.String())
	replayRequest.Header.Set("If-Match", strconv.FormatInt(preview.CycleVersion, 10))
	replayRequest.Header.Set("Idempotency-Key", "relationship-http-commit")
	replayed := httptest.NewRecorder()
	handler.ServeHTTP(replayed, replayRequest)
	if replayed.Code != http.StatusOK || replayed.Header().Get("Idempotency-Replayed") != "true" || replayed.Body.String() != committed.Body.String() {
		t.Fatalf("replay response=%d headers=%v body=%s", replayed.Code, replayed.Header(), replayed.Body.String())
	}

	reusedRequest := cycleRequest(http.MethodPost, path+"/relationship-commits", commitBody, userdom.RoleReviewer, tenantID.String())
	reusedRequest.Header.Set("If-Match", strconv.FormatInt(preview.CycleVersion, 10))
	reusedRequest.Header.Set("Idempotency-Key", "relationship-http-reuse")
	reused := httptest.NewRecorder()
	handler.ServeHTTP(reused, reusedRequest)
	if reused.Code != http.StatusConflict || !strings.Contains(reused.Body.String(), cycleuc.CodeRelationshipPreviewStale) {
		t.Fatalf("reused token response=%d body=%s", reused.Code, reused.Body.String())
	}
}

func TestAssessmentCycleRoutesPermissionAndIdempotency(t *testing.T) {
	router, _, _ := newAssessmentCycleHTTPRouter(t, true, func(string) bool { return true })
	handler := router.routes()

	missingKey := cycleRequest(http.MethodPost, "/api/v1/engagements", `{"name":"Acme"}`, userdom.RoleConsultant, "tenant-1")
	missingKeyResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingKeyResponse, missingKey)
	if missingKeyResponse.Code != http.StatusBadRequest || !strings.Contains(missingKeyResponse.Body.String(), cycleuc.CodeIdempotencyKeyRequired) {
		t.Fatalf("missing key response = %d %s", missingKeyResponse.Code, missingKeyResponse.Body.String())
	}

	create := cycleRequest(http.MethodPost, "/api/v1/engagements", `{"name":"Acme","in_scope":[{"kind":"domain","value":"app.example.com"}]}`, userdom.RoleConsultant, "tenant-1")
	create.Header.Set("Idempotency-Key", "create-1")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create response = %d %s", created.Code, created.Body.String())
	}
	var engagement struct{ ID shared.ID }
	if err := json.Unmarshal(created.Body.Bytes(), &engagement); err != nil {
		t.Fatal(err)
	}

	replay := cycleRequest(http.MethodPost, "/api/v1/engagements", `{"name":"Acme","in_scope":[{"kind":"domain","value":"app.example.com"}]}`, userdom.RoleConsultant, "tenant-1")
	replay.Header.Set("Idempotency-Key", "create-1")
	replayed := httptest.NewRecorder()
	handler.ServeHTTP(replayed, replay)
	if replayed.Code != http.StatusCreated || replayed.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replay response = %d headers=%v", replayed.Code, replayed.Header())
	}

	lifecyclePath := "/api/v1/engagements/" + engagement.ID.String() + "/lifecycle"
	crossTenant := cycleRequest(http.MethodGet, lifecyclePath, "", userdom.RoleReadOnly, "tenant-2")
	crossTenantResponse := httptest.NewRecorder()
	handler.ServeHTTP(crossTenantResponse, crossTenant)
	if crossTenantResponse.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant lifecycle = %d %s", crossTenantResponse.Code, crossTenantResponse.Body.String())
	}

	retestPath := "/api/v1/engagements/" + engagement.ID.String() + "/retests"
	reviewerRetest := cycleRequest(http.MethodPost, retestPath, `{}`, userdom.RoleReviewer, "tenant-1")
	reviewerRetest.Header.Set("Idempotency-Key", "retest-denied")
	reviewerRetestResponse := httptest.NewRecorder()
	handler.ServeHTTP(reviewerRetestResponse, reviewerRetest)
	if reviewerRetestResponse.Code != http.StatusForbidden {
		t.Fatalf("reviewer retest = %d", reviewerRetestResponse.Code)
	}

	retest := cycleRequest(http.MethodPost, retestPath, `{}`, userdom.RoleConsultant, "tenant-1")
	retest.Header.Set("Idempotency-Key", "retest-1")
	retestResponse := httptest.NewRecorder()
	handler.ServeHTTP(retestResponse, retest)
	if retestResponse.Code != http.StatusCreated {
		t.Fatalf("retest response = %d %s", retestResponse.Code, retestResponse.Body.String())
	}

	lifecycle := cycleRequest(http.MethodGet, lifecyclePath, "", userdom.RoleReadOnly, "tenant-1")
	lifecycleResponse := httptest.NewRecorder()
	handler.ServeHTTP(lifecycleResponse, lifecycle)
	if lifecycleResponse.Code != http.StatusOK {
		t.Fatalf("lifecycle response = %d %s", lifecycleResponse.Code, lifecycleResponse.Body.String())
	}
	var lifecycleBody cycleuc.LifecycleView
	if err := json.Unmarshal(lifecycleResponse.Body.Bytes(), &lifecycleBody); err != nil {
		t.Fatal(err)
	}

	archivePath := "/api/v1/assessment-cycles/" + lifecycleBody.Cycle.ID + "/archive"
	consultantArchive := cycleRequest(http.MethodPost, archivePath, "", userdom.RoleConsultant, "tenant-1")
	consultantArchive.Header.Set("Idempotency-Key", "archive-denied")
	consultantArchive.Header.Set("If-Match", strconv.FormatInt(lifecycleBody.Cycle.Version, 10))
	consultantArchiveResponse := httptest.NewRecorder()
	handler.ServeHTTP(consultantArchiveResponse, consultantArchive)
	if consultantArchiveResponse.Code != http.StatusForbidden {
		t.Fatalf("consultant archive = %d", consultantArchiveResponse.Code)
	}

	archive := cycleRequest(http.MethodPost, archivePath, "", userdom.RoleReviewer, "tenant-1")
	archive.Header.Set("Idempotency-Key", "archive-1")
	archive.Header.Set("If-Match", `"`+strconv.FormatInt(lifecycleBody.Cycle.Version, 10)+`"`)
	archiveResponse := httptest.NewRecorder()
	handler.ServeHTTP(archiveResponse, archive)
	if archiveResponse.Code != http.StatusOK {
		t.Fatalf("archive response = %d %s", archiveResponse.Code, archiveResponse.Body.String())
	}
}

func TestAssessmentCycleDualWriteTenantRollout(t *testing.T) {
	router, cycles, observer := newAssessmentCycleHTTPRouter(t, false, func(tenantID string) bool { return tenantID == "tenant-a" })
	handler := router.routes()
	body := `{"name":"Acme","in_scope":[{"kind":"domain","value":"app.example.com"}]}`

	missingKey := cycleRequest(http.MethodPost, "/api/v1/engagements", body, userdom.RoleConsultant, "tenant-a")
	missingKeyResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingKeyResponse, missingKey)
	if missingKeyResponse.Code != http.StatusBadRequest || observer.count("failed") != 1 {
		t.Fatalf("tenant-a missing key = %d outcomes=%v body=%s", missingKeyResponse.Code, observer.outcomes, missingKeyResponse.Body.String())
	}

	tenantA := cycleRequest(http.MethodPost, "/api/v1/engagements", body, userdom.RoleConsultant, "tenant-a")
	tenantA.Header.Set("Idempotency-Key", "tenant-a-create")
	tenantAResponse := httptest.NewRecorder()
	handler.ServeHTTP(tenantAResponse, tenantA)
	if tenantAResponse.Code != http.StatusCreated || tenantAResponse.Header().Get("X-Synapse-Assessment-Cycle-Dual-Write") != "true" || observer.count("created") != 1 {
		t.Fatalf("tenant-a create = %d headers=%v outcomes=%v body=%s", tenantAResponse.Code, tenantAResponse.Header(), observer.outcomes, tenantAResponse.Body.String())
	}

	replay := cycleRequest(http.MethodPost, "/api/v1/engagements", body, userdom.RoleConsultant, "tenant-a")
	replay.Header.Set("Idempotency-Key", "tenant-a-create")
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusCreated || replayResponse.Header().Get("Idempotency-Replayed") != "true" || replayResponse.Body.String() != tenantAResponse.Body.String() || observer.count("replayed") != 1 {
		t.Fatalf("tenant-a replay = %d headers=%v outcomes=%v body=%s", replayResponse.Code, replayResponse.Header(), observer.outcomes, replayResponse.Body.String())
	}

	tenantB := cycleRequest(http.MethodPost, "/api/v1/engagements", body, userdom.RoleConsultant, "tenant-b")
	tenantBResponse := httptest.NewRecorder()
	handler.ServeHTTP(tenantBResponse, tenantB)
	if tenantBResponse.Code != http.StatusCreated || tenantBResponse.Header().Get("X-Synapse-Assessment-Cycle-Dual-Write") != "" || observer.count("legacy") != 1 {
		t.Fatalf("tenant-b legacy create = %d headers=%v outcomes=%v body=%s", tenantBResponse.Code, tenantBResponse.Header(), observer.outcomes, tenantBResponse.Body.String())
	}

	for tenantID, want := range map[shared.ID]int{"tenant-a": 1, "tenant-b": 0} {
		records, err := cycles.ListCycles(context.Background(), ports.AssessmentCycleListQuery{TenantID: tenantID, Limit: 10})
		if err != nil || len(records) != want {
			t.Fatalf("tenant %s cycle count = %d, want %d, err=%v", tenantID, len(records), want, err)
		}
	}
}

func TestAssessmentCycleDualWriteDisabledPreservesLegacyResponse(t *testing.T) {
	configured, cycles, observer := newAssessmentCycleHTTPRouter(t, false, func(string) bool { return false })
	legacy, _, _ := newAssessmentCycleHTTPRouter(t, false, func(string) bool { return false })
	legacy.assessmentCycles = nil
	legacy.assessmentCycleDualWrite = nil

	body := `{"name":"Acme","in_scope":[{"kind":"domain","value":"app.example.com"}]}`
	configuredResponse := httptest.NewRecorder()
	configured.routes().ServeHTTP(configuredResponse, cycleRequest(http.MethodPost, "/api/v1/engagements", body, userdom.RoleConsultant, "tenant-a"))
	legacyResponse := httptest.NewRecorder()
	legacy.routes().ServeHTTP(legacyResponse, cycleRequest(http.MethodPost, "/api/v1/engagements", body, userdom.RoleConsultant, "tenant-a"))

	if configuredResponse.Code != legacyResponse.Code || configuredResponse.Body.String() != legacyResponse.Body.String() {
		t.Fatalf("disabled dual-write response changed: configured=(%d,%q) legacy=(%d,%q)", configuredResponse.Code, configuredResponse.Body.String(), legacyResponse.Code, legacyResponse.Body.String())
	}
	if configuredResponse.Header().Get("X-Synapse-Assessment-Cycle-Dual-Write") != "" || observer.count("legacy") != 1 {
		t.Fatalf("disabled dual-write headers=%v outcomes=%v", configuredResponse.Header(), observer.outcomes)
	}
	records, err := cycles.ListCycles(context.Background(), ports.AssessmentCycleListQuery{TenantID: "tenant-a", Limit: 10})
	if err != nil || len(records) != 0 {
		t.Fatalf("disabled dual-write cycle count = %d, err=%v", len(records), err)
	}
}

func cycleRequest(method, target, body string, role userdom.Role, tenantID string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	principal := Principal{ID: "actor-1", Role: string(role), TenantID: tenantID}
	return request.WithContext(context.WithValue(request.Context(), principalKey, principal))
}
