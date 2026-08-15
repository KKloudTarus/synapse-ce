package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/slauc"
)

type slaHTTPClock struct{ now time.Time }

func (c *slaHTTPClock) Now() time.Time { return c.now }

type slaHTTPIDs struct{ n int }

func (ids *slaHTTPIDs) NewID() shared.ID {
	ids.n++
	return shared.ID(fmt.Sprintf("http-event-%d", ids.n))
}

func newSLARouter(t *testing.T) (*Router, *slauc.Service) {
	t.Helper()
	service, err := slauc.NewService(memory.NewSLAStore(), &slaHTTPClock{now: time.Date(2026, 8, 15, 14, 0, 0, 0, time.UTC)}, &slaHTTPIDs{})
	if err != nil {
		t.Fatal(err)
	}
	router := &Router{log: discardLog()}
	router.SetSLA(service)
	ctx := slaHTTPContext("seed", "admin")
	if _, err := service.Assess(ctx, sla.AssessmentInput{
		TenantID: "tenant-a", EngagementID: "eng-1", FindingID: "finding-1",
		Risk: sla.Inputs{Severity: shared.SeverityHigh, CVSSScore: 8.1, EPSS: 0.4, Feasibility: sla.FeasibilityPatchAvailable},
	}); err != nil {
		t.Fatal(err)
	}
	return router, service
}

func slaHTTPContext(id, role string) context.Context {
	ctx := context.WithValue(context.Background(), principalKey, Principal{ID: id, Name: id, Role: role, TenantID: "tenant-a"})
	return shared.WithTenant(ctx, "tenant-a")
}

func slaHTTPRequest(method, target, id, role string, body []byte) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body)).WithContext(slaHTTPContext(id, role))
	req.SetPathValue("id", "eng-1")
	req.SetPathValue("fid", "finding-1")
	return req
}

func TestSLAListGetHistoryAndEventsHandlers(t *testing.T) {
	router, service := newSLARouter(t)

	listRecorder := httptest.NewRecorder()
	router.listEngagementSLAs(listRecorder, slaHTTPRequest(http.MethodGet, "/api/v1/engagements/eng-1/slas", "reader", "readonly", nil))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	var listBody struct {
		SLAs []sla.View `json:"slas"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listBody); err != nil || len(listBody.SLAs) != 1 || listBody.SLAs[0].Assessment.FindingID != "finding-1" {
		t.Fatalf("list body=%s err=%v", listRecorder.Body.String(), err)
	}

	getRecorder := httptest.NewRecorder()
	router.getFindingSLA(getRecorder, slaHTTPRequest(http.MethodGet, "/api/v1/engagements/eng-1/slas/finding-1", "reader", "readonly", nil))
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", getRecorder.Code, getRecorder.Body.String())
	}

	ctx := slaHTTPContext("reviewer", "reviewer")
	if _, err := service.Transition(ctx, "tenant-a", "eng-1", "finding-1", sla.TransitionCommand{
		To: sla.RemediationMitigating, Actor: "reviewer", Reason: "patch scheduled", ExpectedVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}
	historyRecorder := httptest.NewRecorder()
	router.listSLAAssessments(historyRecorder, slaHTTPRequest(http.MethodGet, "/history", "reader", "readonly", nil))
	if historyRecorder.Code != http.StatusOK || !bytes.Contains(historyRecorder.Body.Bytes(), []byte(`"assessments"`)) {
		t.Fatalf("history status=%d body=%s", historyRecorder.Code, historyRecorder.Body.String())
	}
	eventsRecorder := httptest.NewRecorder()
	router.listSLAEvents(eventsRecorder, slaHTTPRequest(http.MethodGet, "/events", "reader", "readonly", nil))
	if eventsRecorder.Code != http.StatusOK || !bytes.Contains(eventsRecorder.Body.Bytes(), []byte(`"patch scheduled"`)) {
		t.Fatalf("events status=%d body=%s", eventsRecorder.Code, eventsRecorder.Body.String())
	}
}

func TestSLATransitionHandlerRequiresReviewPermissionAndAttributesHuman(t *testing.T) {
	router, _ := newSLARouter(t)
	body := []byte(`{"to":"mitigating","reason":"maintenance approved","version":1}`)

	memberRecorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.transitionFindingSLA)(memberRecorder,
		slaHTTPRequest(http.MethodPost, "/transition", "member", "member", body))
	if memberRecorder.Code != http.StatusForbidden {
		t.Fatalf("member status=%d body=%s", memberRecorder.Code, memberRecorder.Body.String())
	}

	reviewerRecorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.transitionFindingSLA)(reviewerRecorder,
		slaHTTPRequest(http.MethodPost, "/transition", "alice", "reviewer", body))
	if reviewerRecorder.Code != http.StatusOK {
		t.Fatalf("reviewer status=%d body=%s", reviewerRecorder.Code, reviewerRecorder.Body.String())
	}
	var updated sla.View
	if err := json.Unmarshal(reviewerRecorder.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Lifecycle.Status != sla.RemediationMitigating || updated.Lifecycle.UpdatedBy != "alice" || updated.Lifecycle.Version != 2 {
		t.Fatalf("unexpected transition response: %+v", updated.Lifecycle)
	}

	staleRecorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.transitionFindingSLA)(staleRecorder,
		slaHTTPRequest(http.MethodPost, "/transition", "alice", "reviewer", []byte(`{"to":"remediated","reason":"stale","version":1}`)))
	if staleRecorder.Code != http.StatusConflict {
		t.Fatalf("stale status=%d body=%s", staleRecorder.Code, staleRecorder.Body.String())
	}
}

func TestSLAAcceptedRiskHandlerRequiresControlAndExpiry(t *testing.T) {
	router, _ := newSLARouter(t)
	invalid := []byte(`{"to":"accepted_risk","reason":"vendor exception","version":1}`)
	recorder := httptest.NewRecorder()
	router.transitionFindingSLA(recorder, slaHTTPRequest(http.MethodPost, "/transition", "alice", "reviewer", invalid))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid acceptance status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	expiry := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)
	valid, _ := json.Marshal(map[string]any{
		"to": "accepted_risk", "reason": "vendor exception", "version": 1,
		"compensating_control": "WAF plus isolation", "acceptance_expires_at": expiry,
	})
	recorder = httptest.NewRecorder()
	router.transitionFindingSLA(recorder, slaHTTPRequest(http.MethodPost, "/transition", "alice", "reviewer", valid))
	if recorder.Code != http.StatusOK {
		t.Fatalf("valid acceptance status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSLAPolicyHandlersAreAdminOnlyAndVersioned(t *testing.T) {
	router, _ := newSLARouter(t)
	listRecorder := httptest.NewRecorder()
	router.listSLAPolicies(listRecorder, slaHTTPRequest(http.MethodGet, "/api/v1/sla/policies", "reader", "readonly", nil))
	if listRecorder.Code != http.StatusOK || !bytes.Contains(listRecorder.Body.Bytes(), []byte(`"active"`)) {
		t.Fatalf("policy list status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}

	cfg := sla.DefaultConfig()
	cfg.Version = "tenant-policy-2"
	body, _ := json.Marshal(map[string]any{"config": cfg})
	reviewerRecorder := httptest.NewRecorder()
	router.authz(userdom.PermAdminister, router.activateSLAPolicy)(reviewerRecorder,
		slaHTTPRequest(http.MethodPost, "/api/v1/sla/policies", "reviewer", "reviewer", body))
	if reviewerRecorder.Code != http.StatusForbidden {
		t.Fatalf("reviewer activated policy: status=%d", reviewerRecorder.Code)
	}
	adminRecorder := httptest.NewRecorder()
	router.authz(userdom.PermAdminister, router.activateSLAPolicy)(adminRecorder,
		slaHTTPRequest(http.MethodPost, "/api/v1/sla/policies", "admin", "admin", body))
	if adminRecorder.Code != http.StatusCreated || !bytes.Contains(adminRecorder.Body.Bytes(), []byte(`"tenant-policy-2"`)) {
		t.Fatalf("admin status=%d body=%s", adminRecorder.Code, adminRecorder.Body.String())
	}
}

func TestSLAHandlersRejectUnknownJSONFields(t *testing.T) {
	router, _ := newSLARouter(t)
	recorder := httptest.NewRecorder()
	router.transitionFindingSLA(recorder, slaHTTPRequest(http.MethodPost, "/transition", "alice", "reviewer",
		[]byte(`{"to":"mitigating","reason":"x","version":1,"machine_override":true}`)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
