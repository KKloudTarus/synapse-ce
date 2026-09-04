package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	relationshipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentrelationship"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAssessmentRelationshipRoutesEnforceReviewContractsAndIsolation(t *testing.T) {
	router, cycles := newAssessmentRelationshipHTTPRouter(t)
	handler := router.routes()
	generatePath := "/api/v1/assessment-relationship-candidates/generate"
	generateBody := `{"predecessor_cycle_id":"relationship-http-predecessor","successor_cycle_id":"relationship-http-successor","imported_reference_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`

	forbidden := httptest.NewRecorder()
	handler.ServeHTTP(forbidden, cycleRequest(http.MethodPost, generatePath, generateBody, userdom.RoleConsultant, "tenant-relationship-http"))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("consultant generate=%d body=%s", forbidden.Code, forbidden.Body.String())
	}

	unknownMetadata := httptest.NewRecorder()
	handler.ServeHTTP(unknownMetadata, cycleRequest(http.MethodPost, generatePath, `{"predecessor_cycle_id":"relationship-http-predecessor","successor_cycle_id":"relationship-http-successor","imported_reference":{"raw":"secret"}}`, userdom.RoleReviewer, "tenant-relationship-http"))
	if unknownMetadata.Code != http.StatusBadRequest || strings.Contains(unknownMetadata.Body.String(), "secret") {
		t.Fatalf("raw imported metadata=%d body=%s", unknownMetadata.Code, unknownMetadata.Body.String())
	}

	created := httptest.NewRecorder()
	handler.ServeHTTP(created, cycleRequest(http.MethodPost, generatePath, generateBody, userdom.RoleReviewer, "tenant-relationship-http"))
	if created.Code != http.StatusCreated || created.Header().Get("ETag") != `"1"` || strings.Contains(created.Body.String(), "imported_reference_hash") {
		t.Fatalf("generate=%d headers=%v body=%s", created.Code, created.Header(), created.Body.String())
	}
	var candidate relationshipuc.View
	if err := json.Unmarshal(created.Body.Bytes(), &candidate); err != nil || candidate.ID.IsZero() || candidate.Status != relationshipuc.StatusOpen {
		t.Fatalf("candidate=%+v err=%v", candidate, err)
	}

	crossTenant := httptest.NewRecorder()
	handler.ServeHTTP(crossTenant, cycleRequest(http.MethodGet, "/api/v1/assessment-relationship-candidates/"+candidate.ID.String(), "", userdom.RoleReviewer, "other-tenant"))
	if crossTenant.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get=%d body=%s", crossTenant.Code, crossTenant.Body.String())
	}

	decisionPath := "/api/v1/assessment-relationship-candidates/" + candidate.ID.String() + "/decisions"
	decisionBody := `{"action":"confirm","reason":"Reviewed deterministic migration evidence"}`
	missingIfMatch := cycleRequest(http.MethodPost, decisionPath, decisionBody, userdom.RoleReviewer, "tenant-relationship-http")
	missingIfMatch.Header.Set("Idempotency-Key", "relationship-http-confirm")
	missingIfMatchResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingIfMatchResponse, missingIfMatch)
	if missingIfMatchResponse.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match=%d body=%s", missingIfMatchResponse.Code, missingIfMatchResponse.Body.String())
	}

	missingKey := cycleRequest(http.MethodPost, decisionPath, decisionBody, userdom.RoleReviewer, "tenant-relationship-http")
	missingKey.Header.Set("If-Match", `"1"`)
	missingKeyResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingKeyResponse, missingKey)
	if missingKeyResponse.Code != http.StatusBadRequest || !strings.Contains(missingKeyResponse.Body.String(), "idempotency_key_required") {
		t.Fatalf("missing idempotency=%d body=%s", missingKeyResponse.Code, missingKeyResponse.Body.String())
	}

	oversized := cycleRequest(http.MethodPost, decisionPath, `{"action":"confirm","reason":"`+strings.Repeat("x", int(assessmentRelationshipBodyLimit))+`"}`, userdom.RoleReviewer, "tenant-relationship-http")
	oversized.Header.Set("If-Match", `"1"`)
	oversized.Header.Set("Idempotency-Key", "relationship-http-oversized")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized decision=%d body=%s", oversizedResponse.Code, oversizedResponse.Body.String())
	}

	predecessorBefore, _ := cycles.GetCycle(context.Background(), "tenant-relationship-http", "relationship-http-predecessor")
	successorBefore, _ := cycles.GetCycle(context.Background(), "tenant-relationship-http", "relationship-http-successor")
	predecessorMembersBefore, _ := cycles.ListMembers(context.Background(), "tenant-relationship-http", "relationship-http-predecessor")
	successorMembersBefore, _ := cycles.ListMembers(context.Background(), "tenant-relationship-http", "relationship-http-successor")

	confirm := cycleRequest(http.MethodPost, decisionPath, decisionBody, userdom.RoleReviewer, "tenant-relationship-http")
	confirm.Header.Set("If-Match", `W/"1"`)
	confirm.Header.Set("Idempotency-Key", "relationship-http-confirm")
	confirmed := httptest.NewRecorder()
	handler.ServeHTTP(confirmed, confirm)
	if confirmed.Code != http.StatusOK || confirmed.Header().Get("ETag") != `"2"` || confirmed.Header().Get("Idempotency-Replayed") != "" || !strings.Contains(confirmed.Body.String(), `"execution":"blocked"`) {
		t.Fatalf("confirm=%d headers=%v body=%s", confirmed.Code, confirmed.Header(), confirmed.Body.String())
	}

	replay := cycleRequest(http.MethodPost, decisionPath, decisionBody, userdom.RoleReviewer, "tenant-relationship-http")
	replay.Header.Set("If-Match", `"1"`)
	replay.Header.Set("Idempotency-Key", "relationship-http-confirm")
	replayed := httptest.NewRecorder()
	handler.ServeHTTP(replayed, replay)
	if replayed.Code != http.StatusOK || replayed.Header().Get("Idempotency-Replayed") != "true" || replayed.Body.String() != confirmed.Body.String() {
		t.Fatalf("replay=%d headers=%v body=%s", replayed.Code, replayed.Header(), replayed.Body.String())
	}

	predecessorAfter, _ := cycles.GetCycle(context.Background(), "tenant-relationship-http", "relationship-http-predecessor")
	successorAfter, _ := cycles.GetCycle(context.Background(), "tenant-relationship-http", "relationship-http-successor")
	predecessorMembersAfter, _ := cycles.ListMembers(context.Background(), "tenant-relationship-http", "relationship-http-predecessor")
	successorMembersAfter, _ := cycles.ListMembers(context.Background(), "tenant-relationship-http", "relationship-http-successor")
	if !reflect.DeepEqual(predecessorBefore, predecessorAfter) || !reflect.DeepEqual(successorBefore, successorAfter) || !reflect.DeepEqual(predecessorMembersBefore, predecessorMembersAfter) || !reflect.DeepEqual(successorMembersBefore, successorMembersAfter) {
		t.Fatal("HTTP confirmation changed the Assessment Cycle graph")
	}
}

func newAssessmentRelationshipHTTPRouter(t *testing.T) (*Router, *memory.AssessmentCycleRepository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	clock := relationshipHTTPClock{now: now}
	ids := &relationshipHTTPIDs{}
	cycles := memory.NewAssessmentCycleRepository()
	snapshots := memory.NewAssessmentSnapshotRepository()
	for _, subject := range []struct {
		cycleID, assessmentID, snapshotID shared.ID
		runID                             string
		scope                             string
	}{
		{"relationship-http-predecessor", "relationship-http-assessment-predecessor", "relationship-http-snapshot-predecessor", "relationship-http-run-predecessor", "src/**"},
		{"relationship-http-successor", "relationship-http-assessment-successor", "relationship-http-snapshot-successor", "relationship-http-run-successor", "app/**"},
	} {
		cycle, err := assessmentcycle.NewAssessmentCycle(subject.cycleID, "tenant-relationship-http", subject.cycleID.String(), assessmentcycle.BoundaryProject, "", "relationship-http-project", subject.assessmentID, "operator", now)
		if err != nil {
			t.Fatal(err)
		}
		member, err := assessmentcycle.NewInitialMember("tenant-relationship-http", subject.cycleID, subject.assessmentID, "operator", now)
		if err != nil {
			t.Fatal(err)
		}
		if err := cycles.CreateCycle(ctx, cycle); err != nil {
			t.Fatal(err)
		}
		if err := cycles.CreateMember(ctx, member); err != nil {
			t.Fatal(err)
		}
		snapshot, err := assessmentsnapshot.NewFinalized("tenant-relationship-http", subject.snapshotID, subject.cycleID, subject.assessmentID,
			assessmentsnapshot.Boundary{Kind: assessmentcycle.BoundaryProject, ProjectID: "relationship-http-project"}, "request-"+subject.snapshotID.String(), "operator", now,
			[]assessmentsnapshot.SelectedRun{assessmentRelationshipHTTPRun(t, subject.runID, subject.scope, now)})
		if err != nil {
			t.Fatal(err)
		}
		if _, created, err := snapshots.CreateFinalizedCAS(ctx, snapshot, 0); err != nil || !created {
			t.Fatalf("snapshot created=%v err=%v", created, err)
		}
	}
	service, err := relationshipuc.NewService(memory.NewAssessmentRelationshipRepository(), cycles, snapshots, memory.NewFindingLineageRepository(), memory.NewTenantTransactionRunner(), ids, clock, relationshipHTTPAudit{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := &Router{log: discardLog()}
	router.SetAssessmentRelationships(service)
	return router, cycles
}

func assessmentRelationshipHTTPRun(t *testing.T, runID, scope string, now time.Time) assessmentsnapshot.SelectedRun {
	t.Helper()
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repository.git", "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	finished := now.Add(time.Minute)
	lanes := []scanrun.Lane{{
		TenantID: "tenant-relationship-http", EngagementID: "assessment", ScanRunID: runID, LaneKey: "sca", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
		AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{scope}, StartedAt: now, FinishedAt: &finished,
		ResultRef: "result:" + runID, EvidenceRef: "evidence:" + runID, ResultSHA256: strings.Repeat("b", 64), ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion, SealedAt: &finished,
		Versions: []scanrun.LaneVersion{{VersionKind: scanrun.VersionScanner, Name: "sca", Version: "1"}}, Stages: []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: now, FinishedAt: &finished}},
	}}
	lanes[0].ManifestHash, err = scanrun.ComputeManifestHash(lanes[0])
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := scanrun.ComputeRunManifestHash(lanes)
	if err != nil {
		t.Fatal(err)
	}
	return assessmentsnapshot.SelectedRun{ID: runID, ManifestHash: manifestHash, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded, Trusted: true, Lanes: lanes}
}

type relationshipHTTPClock struct{ now time.Time }

func (clock relationshipHTTPClock) Now() time.Time { return clock.now }

type relationshipHTTPIDs struct{ next atomic.Int64 }

func (ids *relationshipHTTPIDs) NewID() shared.ID {
	return shared.ID(fmt.Sprintf("relationship-http-%d", ids.next.Add(1)))
}

type relationshipHTTPAudit struct{}

func (relationshipHTTPAudit) Record(context.Context, ports.AuditEntry) error { return nil }
