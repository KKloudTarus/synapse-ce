package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
)

func TestAssessmentComparisonRoutesContractPermissionsAndIsolation(t *testing.T) {
	router, service, baselineID, currentID := newAssessmentComparisonHTTPRouter(t)
	handler := router.routes()
	body := `{"baseline_snapshot_id":"` + baselineID.String() + `","current_snapshot_id":"` + currentID.String() + `","mode":"lifecycle"}`

	forbidden := httptest.NewRecorder()
	handler.ServeHTTP(forbidden, cycleRequest(http.MethodPost, "/api/v1/assessment-comparisons", body, userdom.RoleReviewer, "tenant-comparison-http"))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("reviewer create=%d body=%s", forbidden.Code, forbidden.Body.String())
	}

	missingKey := httptest.NewRecorder()
	handler.ServeHTTP(missingKey, cycleRequest(http.MethodPost, "/api/v1/assessment-comparisons", body, userdom.RoleConsultant, "tenant-comparison-http"))
	if missingKey.Code != http.StatusBadRequest || !strings.Contains(missingKey.Body.String(), comparisonuc.CodeIdempotencyKeyRequired) {
		t.Fatalf("missing key=%d body=%s", missingKey.Code, missingKey.Body.String())
	}

	create := cycleRequest(http.MethodPost, "/api/v1/assessment-comparisons", body, userdom.RoleConsultant, "tenant-comparison-http")
	create.Header.Set("Idempotency-Key", "comparison-http-create")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusAccepted {
		t.Fatalf("create=%d body=%s", created.Code, created.Body.String())
	}
	var queued comparisonuc.QueueResult
	if err := json.Unmarshal(created.Body.Bytes(), &queued); err != nil || queued.Comparison.ID.IsZero() {
		t.Fatalf("queued=%+v err=%v", queued, err)
	}

	replay := cycleRequest(http.MethodPost, "/api/v1/assessment-comparisons", body, userdom.RoleConsultant, "tenant-comparison-http")
	replay.Header.Set("Idempotency-Key", "comparison-http-create")
	replayed := httptest.NewRecorder()
	handler.ServeHTTP(replayed, replay)
	if replayed.Code != http.StatusAccepted || replayed.Header().Get("Idempotency-Replayed") != "true" || replayed.Body.String() != created.Body.String() {
		t.Fatalf("replay=%d headers=%v body=%s", replayed.Code, replayed.Header(), replayed.Body.String())
	}

	crossTenant := httptest.NewRecorder()
	handler.ServeHTTP(crossTenant, cycleRequest(http.MethodGet, "/api/v1/assessment-comparisons/"+queued.Comparison.ID.String(), "", userdom.RoleReadOnly, "tenant-other"))
	if crossTenant.Code != http.StatusNotFound {
		t.Fatalf("cross tenant get=%d body=%s", crossTenant.Code, crossTenant.Body.String())
	}

	completed, err := service.Generate(context.Background(), comparisonuc.WorkInput{TenantID: "tenant-comparison-http", ComparisonID: queued.Comparison.ID, Actor: "worker"})
	if err != nil || completed.Status != domain.StatusComplete {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, cycleRequest(http.MethodGet, "/api/v1/assessment-comparisons/"+completed.ID.String(), "", userdom.RoleReadOnly, "tenant-comparison-http"))
	if get.Code != http.StatusOK || get.Header().Get("ETag") != `"3"` {
		t.Fatalf("get=%d headers=%v body=%s", get.Code, get.Header(), get.Body.String())
	}

	items := httptest.NewRecorder()
	handler.ServeHTTP(items, cycleRequest(http.MethodGet, "/api/v1/assessment-comparisons/"+completed.ID.String()+"/items?limit=1", "", userdom.RoleReadOnly, "tenant-comparison-http"))
	if items.Code != http.StatusOK || !strings.Contains(items.Body.String(), "comparison-item-") {
		t.Fatalf("items=%d body=%s", items.Code, items.Body.String())
	}
	invalidCursor := httptest.NewRecorder()
	handler.ServeHTTP(invalidCursor, cycleRequest(http.MethodGet, "/api/v1/assessment-comparisons/"+completed.ID.String()+"/items?cursor=not-base64", "", userdom.RoleReadOnly, "tenant-comparison-http"))
	if invalidCursor.Code != http.StatusBadRequest || !strings.Contains(invalidCursor.Body.String(), "invalid_cursor") {
		t.Fatalf("invalid cursor=%d body=%s", invalidCursor.Code, invalidCursor.Body.String())
	}

	reviewPath := "/api/v1/assessment-comparisons/" + completed.ID.String() + "/items/missing/confirm"
	consultantReview := httptest.NewRecorder()
	handler.ServeHTTP(consultantReview, cycleRequest(http.MethodPost, reviewPath, `{}`, userdom.RoleConsultant, "tenant-comparison-http"))
	if consultantReview.Code != http.StatusForbidden {
		t.Fatalf("consultant review=%d body=%s", consultantReview.Code, consultantReview.Body.String())
	}
	missingIfMatch := cycleRequest(http.MethodPost, reviewPath, `{}`, userdom.RoleReviewer, "tenant-comparison-http")
	missingIfMatch.Header.Set("Idempotency-Key", "review-http")
	missingIfMatchResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingIfMatchResponse, missingIfMatch)
	if missingIfMatchResponse.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match=%d body=%s", missingIfMatchResponse.Code, missingIfMatchResponse.Body.String())
	}
}

func newAssessmentComparisonHTTPRouter(t *testing.T) (*Router, *comparisonuc.Service, shared.ID, shared.ID) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)
	clock := fixedClock{t: now}
	ids := &assessmentCycleHTTPIDs{}
	audit := &fakeAudit{}
	transactions := memory.NewTenantTransactionRunner()
	cycles := memory.NewAssessmentCycleRepository()
	snapshots := memory.NewAssessmentSnapshotRepository()
	lineage := memory.NewFindingLineageRepository()
	comparisons := memory.NewAssessmentComparisonRepository()
	cycle, err := assessmentcycle.NewAssessmentCycle("comparison-http-cycle", "tenant-comparison-http", "HTTP Cycle", assessmentcycle.BoundaryStandalone, "", "", "comparison-http-assessment", "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember("tenant-comparison-http", cycle.ID, "comparison-http-assessment", "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	retest, err := assessmentcycle.NewRetestMember("tenant-comparison-http", cycle.ID, "comparison-http-retest", member.AssessmentID, 1, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, retest); err != nil {
		t.Fatal(err)
	}
	var baselineID, currentID shared.ID
	for number, value := range []struct {
		id, runID, assessmentID shared.ID
		scope                   string
	}{{"comparison-http-snapshot-1", "comparison-http-run-1", member.AssessmentID, "src/**"}, {"comparison-http-snapshot-2", "comparison-http-run-2", retest.AssessmentID, "src/**"}} {
		snapshot, err := assessmentsnapshot.NewFinalized("tenant-comparison-http", value.id, cycle.ID, value.assessmentID,
			assessmentsnapshot.Boundary{Kind: assessmentcycle.BoundaryStandalone}, "request-"+value.id.String(), "operator", now.Add(time.Duration(number)*time.Minute),
			[]assessmentsnapshot.SelectedRun{assessmentRelationshipHTTPRun(t, value.runID.String(), value.scope, now.Add(time.Duration(number)*time.Minute))})
		if err != nil {
			t.Fatal(err)
		}
		stored, created, err := snapshots.CreateFinalizedCAS(ctx, snapshot, 0)
		if err != nil || !created {
			t.Fatalf("snapshot %d created=%v err=%v", number+1, created, err)
		}
		if number == 0 {
			baselineID = stored.ID
		} else {
			currentID = stored.ID
		}
	}
	canonical, err := findinglineage.CanonicalizeFingerprintV1(findinglineage.FingerprintCanonicalInputV1{
		CanonicalizationVersion: 1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: "repository:https://example.com/repository.git@0123456789abcdef0123456789abcdef01234567",
		IdentityFields: map[string]findinglineage.CanonicalValue{"rule_id": findinglineage.Text("rule-http")},
	})
	if err != nil {
		t.Fatal(err)
	}
	risk := 5000
	identity := findinglineage.Identity{
		TenantID: "tenant-comparison-http", CycleID: cycle.ID, ID: "comparison-http-identity", ProducerKind: "sca", FindingKind: "vulnerability",
		CanonicalizationVersion: 1, FingerprintSchemaVersion: 1, LineageFingerprint: canonical.Fingerprint, TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical: "repository:https://example.com/repository.git@0123456789abcdef0123456789abcdef01234567", CanonicalIdentityFields: canonical.IdentityFields,
		FirstSeenSnapshotID: baselineID, CreatedAt: now,
	}
	observation := func(id, snapshotID shared.ID, observedAt time.Time) findinglineage.Observation {
		return findinglineage.Observation{
			TenantID: identity.TenantID, CycleID: cycle.ID, ID: id, SnapshotID: snapshotID, IdentityID: identity.ID, ProducerKind: "sca", FindingKind: "vulnerability",
			TargetCanonical: identity.TargetIdentityCanonical, SourceFindingID: "source-" + id.String(), Severity: shared.SeverityHigh, RiskScoreMilli: &risk,
			ComponentVersion: "1.0.0", Location: "go.mod", Reachability: "reachable", EvidenceDigest: strings.Repeat("a", 64),
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "sca", ToolVersion: "1", LaneKey: "sca", RuleID: "rule-http"}, ObservedAt: observedAt,
		}
	}
	if err := lineage.CreateIdentityWithObservation(ctx, identity, observation("comparison-http-observation-1", baselineID, now)); err != nil {
		t.Fatal(err)
	}
	if err := lineage.AppendObservation(ctx, observation("comparison-http-observation-2", currentID, now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	verification, err := comparisonuc.NewRetestVerificationReader(lineage, snapshots, memory.NewRetestRepository())
	if err != nil {
		t.Fatal(err)
	}
	service, err := comparisonuc.NewService(comparisons, snapshots, cycles, lineage, transactions, audit, clock, ids, verification, nil)
	if err != nil {
		t.Fatal(err)
	}
	lineageService, err := lineageuc.NewService(lineage, transactions, audit, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.SetAPIStores(memory.NewAssessmentCycleRequestRepository(), memory.NewJobQueue(ids, clock.Now), lineageService)
	router := &Router{log: discardLog()}
	router.SetAssessmentComparisons(service)
	return router, service, baselineID, currentID
}
