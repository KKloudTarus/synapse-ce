package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAssessmentSnapshotRoutesContractsPermissionsAndTenantIsolation(t *testing.T) {
	router := newAssessmentSnapshotHTTPRouter(t)
	handler := router.routes()
	path := "/api/v1/engagements/assessment-snapshot-http/snapshots/finalize"
	body := `{"selected_runs":[{"run_id":"snapshot-http-run","lane_keys":["sca"]}]}`

	reviewer := cycleRequest(http.MethodPost, path, body, userdom.RoleReviewer, "tenant-snapshot-http")
	reviewer.Header.Set("Idempotency-Key", "snapshot-http-reviewer")
	reviewer.Header.Set("If-Match", "0")
	reviewerResponse := httptest.NewRecorder()
	handler.ServeHTTP(reviewerResponse, reviewer)
	if reviewerResponse.Code != http.StatusForbidden {
		t.Fatalf("reviewer finalize=%d body=%s", reviewerResponse.Code, reviewerResponse.Body.String())
	}

	missingKey := cycleRequest(http.MethodPost, path, body, userdom.RoleConsultant, "tenant-snapshot-http")
	missingKey.Header.Set("If-Match", "0")
	missingKeyResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingKeyResponse, missingKey)
	if missingKeyResponse.Code != http.StatusBadRequest || !strings.Contains(missingKeyResponse.Body.String(), "idempotency_key_required") {
		t.Fatalf("missing key=%d body=%s", missingKeyResponse.Code, missingKeyResponse.Body.String())
	}

	missingIfMatch := cycleRequest(http.MethodPost, path, body, userdom.RoleConsultant, "tenant-snapshot-http")
	missingIfMatch.Header.Set("Idempotency-Key", "snapshot-http-missing-if-match")
	missingIfMatchResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingIfMatchResponse, missingIfMatch)
	if missingIfMatchResponse.Code != http.StatusPreconditionRequired || !strings.Contains(missingIfMatchResponse.Body.String(), "precondition_required") {
		t.Fatalf("missing If-Match=%d body=%s", missingIfMatchResponse.Code, missingIfMatchResponse.Body.String())
	}

	create := cycleRequest(http.MethodPost, path, body, userdom.RoleConsultant, "tenant-snapshot-http")
	create.Header.Set("Idempotency-Key", "snapshot-http-create")
	create.Header.Set("If-Match", `W/"0"`)
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated || created.Header().Get("ETag") != `"1"` || strings.Contains(created.Body.String(), "snapshot-http-create") || strings.Contains(created.Body.String(), "request_hash") {
		t.Fatalf("create=%d headers=%v body=%s", created.Code, created.Header(), created.Body.String())
	}
	var finalized finalizedAssessmentSnapshotResponse
	if err := json.Unmarshal(created.Body.Bytes(), &finalized); err != nil || finalized.Snapshot.ID.IsZero() || finalized.DefaultVersion != 1 {
		t.Fatalf("decode finalized=%+v err=%v", finalized, err)
	}

	replay := cycleRequest(http.MethodPost, path, body, userdom.RoleConsultant, "tenant-snapshot-http")
	replay.Header.Set("Idempotency-Key", "snapshot-http-create")
	replay.Header.Set("If-Match", "0")
	replayed := httptest.NewRecorder()
	handler.ServeHTTP(replayed, replay)
	if replayed.Code != http.StatusCreated || replayed.Header().Get("Idempotency-Replayed") != "true" || replayed.Body.String() != created.Body.String() {
		t.Fatalf("replay=%d headers=%v body=%s", replayed.Code, replayed.Header(), replayed.Body.String())
	}

	mismatch := cycleRequest(http.MethodPost, path, `{"selected_runs":[{"run_id":"snapshot-http-run","lane_keys":["other"]}]}`, userdom.RoleConsultant, "tenant-snapshot-http")
	mismatch.Header.Set("Idempotency-Key", "snapshot-http-create")
	mismatch.Header.Set("If-Match", "0")
	mismatchResponse := httptest.NewRecorder()
	handler.ServeHTTP(mismatchResponse, mismatch)
	if mismatchResponse.Code != http.StatusConflict || !strings.Contains(mismatchResponse.Body.String(), "idempotency_body_mismatch") {
		t.Fatalf("mismatch=%d body=%s", mismatchResponse.Code, mismatchResponse.Body.String())
	}

	listPath := "/api/v1/engagements/assessment-snapshot-http/snapshots"
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, cycleRequest(http.MethodGet, listPath, "", userdom.RoleReadOnly, "tenant-snapshot-http"))
	if list.Code != http.StatusOK || list.Header().Get("ETag") != `"1"` {
		t.Fatalf("list=%d headers=%v body=%s", list.Code, list.Header(), list.Body.String())
	}
	var page assessmentSnapshotListResponse
	if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.DefaultSnapshotID != finalized.Snapshot.ID || page.DefaultVersion != 1 {
		t.Fatalf("list page=%+v err=%v", page, err)
	}

	get := httptest.NewRecorder()
	handler.ServeHTTP(get, cycleRequest(http.MethodGet, "/api/v1/assessment-snapshots/"+finalized.Snapshot.ID.String(), "", userdom.RoleReadOnly, "tenant-snapshot-http"))
	if get.Code != http.StatusOK || get.Header().Get("ETag") != `"sha256:`+finalized.Snapshot.ContentHash+`"` {
		t.Fatalf("get=%d headers=%v body=%s", get.Code, get.Header(), get.Body.String())
	}

	crossTenantList := httptest.NewRecorder()
	handler.ServeHTTP(crossTenantList, cycleRequest(http.MethodGet, listPath, "", userdom.RoleReadOnly, "tenant-other"))
	if crossTenantList.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant list=%d body=%s", crossTenantList.Code, crossTenantList.Body.String())
	}
	crossTenantGet := httptest.NewRecorder()
	handler.ServeHTTP(crossTenantGet, cycleRequest(http.MethodGet, "/api/v1/assessment-snapshots/"+finalized.Snapshot.ID.String(), "", userdom.RoleReadOnly, "tenant-other"))
	if crossTenantGet.Code != http.StatusNotFound || !strings.Contains(crossTenantGet.Body.String(), "not_found") {
		t.Fatalf("cross-tenant get=%d body=%s", crossTenantGet.Code, crossTenantGet.Body.String())
	}
}

func TestAssessmentSnapshotFinalizeRejectsOversizedBody(t *testing.T) {
	router := newAssessmentSnapshotHTTPRouter(t)
	request := cycleRequest(http.MethodPost, "/api/v1/engagements/assessment-snapshot-http/snapshots/finalize", `{"selected_runs":[{"run_id":"`+strings.Repeat("a", int(assessmentSnapshotRequestLimit))+`"}]}`, userdom.RoleConsultant, "tenant-snapshot-http")
	request.Header.Set("Idempotency-Key", "snapshot-http-oversized")
	request.Header.Set("If-Match", "0")
	response := httptest.NewRecorder()
	router.routes().ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "request_too_large") {
		t.Fatalf("oversized=%d body=%s", response.Code, response.Body.String())
	}
}

func newAssessmentSnapshotHTTPRouter(t *testing.T) *Router {
	t.Helper()
	ctx := context.Background()
	clock := fixedClock{t: time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)}
	ids := &assessmentCycleHTTPIDs{}
	audit := &fakeAudit{}
	engagements := memory.NewEngagementRepository()
	assessment, err := engagement.New("assessment-snapshot-http", "tenant-snapshot-http", "Snapshot API", "", clock.t)
	if err != nil {
		t.Fatal(err)
	}
	if err := assessment.Transition(engagement.StatusActive, clock.t); err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, assessment); err != nil {
		t.Fatal(err)
	}
	cycles := memory.NewAssessmentCycleRepository()
	cycle, err := assessmentcycle.NewAssessmentCycle("cycle-snapshot-http", "tenant-snapshot-http", "Snapshot API", assessmentcycle.BoundaryStandalone, "", "", assessment.ID, "operator", clock.t)
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember("tenant-snapshot-http", cycle.ID, assessment.ID, "operator", clock.t)
	if err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	runs := memory.NewScanRunStore()
	run := assessmentSnapshotHTTPRun(t, clock.t)
	begin := run
	begin.Manifest, begin.FindingKeys, begin.Lanes = ports.ScanManifest{}, nil, nil
	begin.TerminalStatus, begin.ManifestSchemaVersion, begin.ManifestHash, begin.SealedAt = scanrun.StatusBuilding, 0, "", nil
	if err := runs.Begin(ctx, begin); err != nil {
		t.Fatal(err)
	}
	if err := runs.Seal(ctx, run); err != nil {
		t.Fatal(err)
	}
	transactions := memory.NewTenantTransactionRunner()
	snapshots := memory.NewAssessmentSnapshotRepository()
	service, err := snapshotuc.NewService(snapshots, cycles, engagements, runs, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	engagementService := enguc.NewService(engagements, clock, ids, audit)
	router := &Router{log: discardLog(), eng: engagementService}
	router.SetAssessmentSnapshots(service)
	return router
}

func assessmentSnapshotHTTPRun(t *testing.T, now time.Time) ports.ScanRun {
	t.Helper()
	target, err := scanrun.CanonicalTarget(scanrun.TargetInput{
		Kind: scanrun.TargetRepository, Raw: "https://example.com/repo.git", EvaluatedRevision: "0123456789abcdef0123456789abcdef01234567", SchemaVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	finished := now.Add(time.Minute)
	run := ports.ScanRun{
		TenantID: "tenant-snapshot-http", ID: "snapshot-http-run", EngagementID: "assessment-snapshot-http", CreatedAt: now,
		Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding,
		Lanes: []scanrun.Lane{{
			Key: "sca", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
			AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{"src/**"}, StartedAt: now, FinishedAt: &finished,
			ResultRef: "result:snapshot-http", EvidenceRef: "evidence:snapshot-http", ResultSHA256: strings.Repeat("a", 64), ManifestSchemaVersion: 1,
			Versions: []scanrun.Version{{Kind: scanrun.VersionScanner, Name: "sca", Version: "1"}}, Stages: []scanrun.Stage{{Key: "scan", Status: scanrun.StageSucceeded}},
		}},
	}
	if err := run.Seal(scanrun.StatusSucceeded, 1, finished); err != nil {
		t.Fatal(err)
	}
	return run
}
