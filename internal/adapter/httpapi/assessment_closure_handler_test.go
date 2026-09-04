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

	closuredom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type closureHTTPDecisionReader struct{}

func (closureHTTPDecisionReader) ListAssessmentClosureReferences(context.Context, shared.ID, ports.AssessmentClosureReferenceQuery) ([]closuredom.Reference, error) {
	return nil, nil
}

func (closureHTTPDecisionReader) ResolveAssessmentClosureReference(context.Context, shared.ID, ports.AssessmentClosureReferenceQuery, closuredom.Reference) error {
	return nil
}

func TestAssessmentClosureReportDownloadHTTP(t *testing.T) {
	router, tenantID, cycleID, manifestID := newAssessmentClosureHTTPRouter(t)
	handler := router.routes()
	path := "/api/v1/assessment-cycles/" + cycleID.String() + "/closure-manifests/" + manifestID.String() + "/report"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, cycleRequest(http.MethodGet, path, "", userdom.RoleReadOnly, tenantID.String()))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("download response=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if response.Header().Get("Content-Disposition") != `attachment; filename="assessment-cycle-closure-report.json"` || !strings.HasPrefix(response.Header().Get("ETag"), `"sha256:`) {
		t.Fatalf("download headers=%v", response.Header())
	}
	var document cycleuc.ClosureReportDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil || document.Report.Manifest.ID != manifestID.String() || document.Report.Cycle.ID != cycleID.String() {
		t.Fatalf("report document=%+v err=%v", document, err)
	}

	notModifiedRequest := cycleRequest(http.MethodGet, path, "", userdom.RoleReadOnly, tenantID.String())
	notModifiedRequest.Header.Set("If-None-Match", response.Header().Get("ETag"))
	notModified := httptest.NewRecorder()
	handler.ServeHTTP(notModified, notModifiedRequest)
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Fatalf("not modified response=%d body=%q", notModified.Code, notModified.Body.String())
	}

	crossTenant := httptest.NewRecorder()
	handler.ServeHTTP(crossTenant, cycleRequest(http.MethodGet, path, "", userdom.RoleReadOnly, "other-tenant"))
	if crossTenant.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant response=%d body=%s", crossTenant.Code, crossTenant.Body.String())
	}
}

func TestAssessmentClosureAndReopenHTTPConcurrencyContracts(t *testing.T) {
	router, tenantID, cycleID, _ := newAssessmentClosureHTTPRouterState(t, false)
	handler := router.routes()
	base := "/api/v1/assessment-cycles/" + cycleID.String()

	previewResponse := httptest.NewRecorder()
	handler.ServeHTTP(previewResponse, cycleRequest(http.MethodPost, base+"/closure-previews", `{"reason":"release accepted"}`, userdom.RoleReviewer, tenantID.String()))
	if previewResponse.Code != http.StatusOK {
		t.Fatalf("closure preview=%d body=%s", previewResponse.Code, previewResponse.Body.String())
	}
	var preview cycleuc.ClosurePreview
	if err := json.Unmarshal(previewResponse.Body.Bytes(), &preview); err != nil || preview.PreviewToken == "" {
		t.Fatalf("closure preview=%+v err=%v", preview, err)
	}
	commitBody := `{"preview_token":"` + preview.PreviewToken + `","reason":"release accepted"}`

	missingIfMatch := httptest.NewRecorder()
	request := cycleRequest(http.MethodPost, base+"/closure-commits", commitBody, userdom.RoleReviewer, tenantID.String())
	request.Header.Set("Idempotency-Key", "closure-http-missing-match")
	handler.ServeHTTP(missingIfMatch, request)
	assertAssessmentCycleHTTPError(t, missingIfMatch, http.StatusPreconditionRequired, "precondition_required")

	missingIdempotency := httptest.NewRecorder()
	request = cycleRequest(http.MethodPost, base+"/closure-commits", commitBody, userdom.RoleReviewer, tenantID.String())
	request.Header.Set("If-Match", `"`+strconv.FormatInt(preview.CycleVersion, 10)+`"`)
	handler.ServeHTTP(missingIdempotency, request)
	assertAssessmentCycleHTTPError(t, missingIdempotency, http.StatusBadRequest, cycleuc.CodeIdempotencyKeyRequired)

	tampered := httptest.NewRecorder()
	tamperedBody := `{"preview_token":"` + preview.PreviewToken + `x","reason":"release accepted"}`
	request = cycleRequest(http.MethodPost, base+"/closure-commits", tamperedBody, userdom.RoleReviewer, tenantID.String())
	request.Header.Set("If-Match", strconv.FormatInt(preview.CycleVersion, 10))
	request.Header.Set("Idempotency-Key", "closure-http-tampered")
	handler.ServeHTTP(tampered, request)
	assertAssessmentCycleHTTPError(t, tampered, http.StatusConflict, cycleuc.CodeClosurePreviewStale)

	committed := httptest.NewRecorder()
	request = cycleRequest(http.MethodPost, base+"/closure-commits", commitBody, userdom.RoleReviewer, tenantID.String())
	request.Header.Set("If-Match", strconv.FormatInt(preview.CycleVersion, 10))
	request.Header.Set("Idempotency-Key", "closure-http-commit-contract")
	handler.ServeHTTP(committed, request)
	if committed.Code != http.StatusCreated {
		t.Fatalf("closure commit=%d body=%s", committed.Code, committed.Body.String())
	}
	var closureResult cycleuc.ClosureCommitResult
	if err := json.Unmarshal(committed.Body.Bytes(), &closureResult); err != nil {
		t.Fatal(err)
	}

	replayed := httptest.NewRecorder()
	request = cycleRequest(http.MethodPost, base+"/closure-commits", commitBody, userdom.RoleReviewer, tenantID.String())
	request.Header.Set("If-Match", strconv.FormatInt(preview.CycleVersion, 10))
	request.Header.Set("Idempotency-Key", "closure-http-commit-contract")
	handler.ServeHTTP(replayed, request)
	if replayed.Code != http.StatusCreated || replayed.Header().Get("Idempotency-Replayed") != "true" || replayed.Body.String() != committed.Body.String() {
		t.Fatalf("closure replay=%d headers=%v body=%s", replayed.Code, replayed.Header(), replayed.Body.String())
	}

	mismatchedBody := httptest.NewRecorder()
	request = cycleRequest(http.MethodPost, base+"/closure-commits", strings.Replace(commitBody, "release accepted", "different reason", 1), userdom.RoleReviewer, tenantID.String())
	request.Header.Set("If-Match", strconv.FormatInt(preview.CycleVersion, 10))
	request.Header.Set("Idempotency-Key", "closure-http-commit-contract")
	handler.ServeHTTP(mismatchedBody, request)
	assertAssessmentCycleHTTPError(t, mismatchedBody, http.StatusConflict, cycleuc.CodeIdempotencyBodyMismatch)

	reusedPreview := httptest.NewRecorder()
	request = cycleRequest(http.MethodPost, base+"/closure-commits", commitBody, userdom.RoleReviewer, tenantID.String())
	request.Header.Set("If-Match", strconv.FormatInt(preview.CycleVersion, 10))
	request.Header.Set("Idempotency-Key", "closure-http-reused-preview")
	handler.ServeHTTP(reusedPreview, request)
	assertAssessmentCycleHTTPError(t, reusedPreview, http.StatusConflict, cycleuc.CodeClosurePreviewStale)

	reopenPreviewResponse := httptest.NewRecorder()
	handler.ServeHTTP(reopenPreviewResponse, cycleRequest(http.MethodPost, base+"/reopen-previews", `{}`, userdom.RoleReviewer, tenantID.String()))
	if reopenPreviewResponse.Code != http.StatusOK {
		t.Fatalf("reopen preview=%d body=%s", reopenPreviewResponse.Code, reopenPreviewResponse.Body.String())
	}
	var reopenPreview cycleuc.ReopenPreview
	if err := json.Unmarshal(reopenPreviewResponse.Body.Bytes(), &reopenPreview); err != nil || reopenPreview.PreviewToken == "" || reopenPreview.Manifest.ID != closureResult.Manifest.ID {
		t.Fatalf("reopen preview=%+v err=%v", reopenPreview, err)
	}
	reopenBody := `{"preview_token":"` + reopenPreview.PreviewToken + `","reason":"additional testing required"}`
	reopened := httptest.NewRecorder()
	request = cycleRequest(http.MethodPost, base+"/reopen-commits", reopenBody, userdom.RoleReviewer, tenantID.String())
	request.Header.Set("If-Match", strconv.FormatInt(reopenPreview.CycleVersion, 10))
	request.Header.Set("Idempotency-Key", "closure-http-reopen-contract")
	handler.ServeHTTP(reopened, request)
	if reopened.Code != http.StatusOK {
		t.Fatalf("reopen commit=%d body=%s", reopened.Code, reopened.Body.String())
	}

	reopenReplay := httptest.NewRecorder()
	request = cycleRequest(http.MethodPost, base+"/reopen-commits", reopenBody, userdom.RoleReviewer, tenantID.String())
	request.Header.Set("If-Match", strconv.FormatInt(reopenPreview.CycleVersion, 10))
	request.Header.Set("Idempotency-Key", "closure-http-reopen-contract")
	handler.ServeHTTP(reopenReplay, request)
	if reopenReplay.Code != http.StatusOK || reopenReplay.Header().Get("Idempotency-Replayed") != "true" || reopenReplay.Body.String() != reopened.Body.String() {
		t.Fatalf("reopen replay=%d headers=%v body=%s", reopenReplay.Code, reopenReplay.Header(), reopenReplay.Body.String())
	}
}

func newAssessmentClosureHTTPRouter(t *testing.T) (*Router, shared.ID, shared.ID, shared.ID) {
	return newAssessmentClosureHTTPRouterState(t, true)
}

func newAssessmentClosureHTTPRouterState(t *testing.T, closeCycle bool) (*Router, shared.ID, shared.ID, shared.ID) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tenantID := shared.ID("tenant-closure-http")
	ids := &assessmentCycleHTTPIDs{}
	clock := fixedClock{t: now}
	audit := &fakeAudit{}
	engagements := memory.NewEngagementRepository()
	cycles := memory.NewAssessmentCycleRepository()
	snapshots := memory.NewAssessmentSnapshotRepository()
	comparisons := memory.NewAssessmentComparisonRepository()
	transactions := memory.NewTenantTransactionRunner()
	queue := memory.NewJobQueue(ids, clock.Now)

	root := completedClosureHTTPAssessment(t, tenantID, "closure-http-root", now)
	final := completedClosureHTTPAssessment(t, tenantID, "closure-http-final", now)
	for _, assessment := range []*engdom.Engagement{root, final} {
		if err := engagements.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
	}
	cycle, err := cycledom.NewAssessmentCycle("closure-http-cycle", tenantID, "Closure HTTP", cycledom.BoundaryStandalone, "", "", root.ID, "owner", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest(final.ID, root.ID, cycle.Version, "owner", now); err != nil {
		t.Fatal(err)
	}
	rootMember, _ := cycledom.NewInitialMember(tenantID, cycle.ID, root.ID, "owner", now)
	finalMember, _ := cycledom.NewRetestMember(tenantID, cycle.ID, final.ID, root.ID, 1, "owner", now)
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	for _, member := range []*cycledom.Member{rootMember, finalMember} {
		if err := cycles.CreateMember(ctx, member); err != nil {
			t.Fatal(err)
		}
	}
	rootSnapshot := closureHTTPSnapshot(t, tenantID, cycle.ID, root.ID, "closure-http-snapshot-root", "closure-http-run-root", now)
	finalSnapshot := closureHTTPSnapshot(t, tenantID, cycle.ID, final.ID, "closure-http-snapshot-final", "closure-http-run-final", now)
	for _, snapshot := range []*assessmentsnapshot.Snapshot{rootSnapshot, finalSnapshot} {
		if _, _, err := snapshots.CreateFinalizedCAS(ctx, snapshot, 0); err != nil {
			t.Fatal(err)
		}
	}
	comparison := closureHTTPComparison(t, tenantID, cycle.ID, rootSnapshot, finalSnapshot, now)
	if _, created, err := comparisons.CreateQueued(ctx, comparison); err != nil || !created {
		t.Fatalf("create comparison created=%v err=%v", created, err)
	}
	if err := comparison.Start(comparison.Version, now); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 1); err != nil {
		t.Fatal(err)
	}
	if err := comparison.Complete(nil, comparison.Version, now); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 2); err != nil {
		t.Fatal(err)
	}

	engagementService := enguc.NewService(engagements, clock, ids, audit)
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	api, err := cycleuc.NewAPIService(cycleService, cycles, memory.NewAssessmentCycleRequestRepository(), engagementService, transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.SetClosureDependencies(cycles, snapshots, comparisons, closureHTTPDecisionReader{}, queue, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	router := &Router{log: discardLog(), eng: engagementService}
	router.SetAssessmentCycles(api, true, func(string) bool { return true })
	if !closeCycle {
		return router, tenantID, cycle.ID, ""
	}
	preview, err := api.PreviewClosure(ctx, cycleuc.ClosurePreviewInput{TenantID: tenantID, Actor: "reviewer", CycleID: cycle.ID, Reason: "release accepted"})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := api.CommitClosure(ctx, cycleuc.ClosureCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: tenantID, Actor: "reviewer", Route: "/closure-commits", IdempotencyKey: "closure-http-commit"},
		CycleID: cycle.ID, ExpectedVersion: preview.CycleVersion, PreviewToken: preview.PreviewToken, Reason: "release accepted",
	})
	if err != nil {
		t.Fatal(err)
	}
	var result cycleuc.ClosureCommitResult
	if err := json.Unmarshal(commit.Body, &result); err != nil {
		t.Fatal(err)
	}
	return router, tenantID, cycle.ID, shared.ID(result.Manifest.ID)
}

func assertAssessmentCycleHTTPError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body errorBody
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != status || body.Error != code {
		t.Fatalf("response=%d body=%s parsed=%+v err=%v want_status=%d want_code=%q", response.Code, response.Body.String(), body, err, status, code)
	}
}

func completedClosureHTTPAssessment(t *testing.T, tenantID, id shared.ID, now time.Time) *engdom.Engagement {
	t.Helper()
	assessment, err := engdom.New(id, tenantID, id.String(), "client", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := assessment.Transition(engdom.StatusActive, now); err != nil {
		t.Fatal(err)
	}
	if err := assessment.Transition(engdom.StatusCompleted, now); err != nil {
		t.Fatal(err)
	}
	return assessment
}

func closureHTTPSnapshot(t *testing.T, tenantID, cycleID, assessmentID, snapshotID shared.ID, runID string, now time.Time) *assessmentsnapshot.Snapshot {
	t.Helper()
	finished := now.Add(-time.Minute)
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repo.git", "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	lanes := []scanrun.Lane{{
		TenantID: tenantID, EngagementID: assessmentID, ScanRunID: runID, LaneKey: runID + "-lane", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{"src/**"}, ExcludedScope: []string{"vendor/**"},
		StartedAt: finished.Add(-time.Minute), FinishedAt: &finished, ResultRef: "result:" + runID, EvidenceRef: "evidence:" + runID,
		ResultSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion, SealedAt: &finished,
		Versions: []scanrun.LaneVersion{{VersionKind: scanrun.VersionScanner, Name: "sca", Version: "1"}}, Stages: []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: finished.Add(-time.Minute), FinishedAt: &finished}},
	}}
	lanes[0].ManifestHash, err = scanrun.ComputeManifestHash(lanes[0])
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := scanrun.ComputeRunManifestHash(lanes)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := assessmentsnapshot.NewFinalized(tenantID, snapshotID, cycleID, assessmentID, assessmentsnapshot.Boundary{Kind: cycledom.BoundaryStandalone}, "request-"+snapshotID.String(), "scanner", now, []assessmentsnapshot.SelectedRun{{
		ID: runID, ManifestHash: manifestHash, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded, Trusted: true, Lanes: lanes,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func closureHTTPComparison(t *testing.T, tenantID, cycleID shared.ID, initial, final *assessmentsnapshot.Snapshot, now time.Time) cmpdom.Comparison {
	t.Helper()
	input := cmpdom.GenerationInput{
		Mode: cmpdom.ModeLifecycle, Baseline: cmpdom.SnapshotHashRef{ID: initial.ID, ContentHash: initial.ContentHash}, Current: cmpdom.SnapshotHashRef{ID: final.ID, ContentHash: final.ContentHash},
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: 1, CoveragePolicyVersion: 1,
	}
	payload, inputHash, err := cmpdom.HashGenerationInput(input)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := cmpdom.NewQueued(tenantID, cycleID, "closure-http-comparison", input, payload, inputHash, now)
	if err != nil {
		t.Fatal(err)
	}
	return comparison
}
