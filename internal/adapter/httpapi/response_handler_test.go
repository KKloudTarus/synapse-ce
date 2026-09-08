package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	responseuc "github.com/KKloudTarus/synapse-ce/internal/usecase/response"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

type fakeResponseSvc struct {
	applied     rdom.Action
	appTarget   engagement.Target
	fingerprint responsesaga.TargetFingerprint
	approver    string
	rec         rdom.Record
	applyErr    error
	decideErr   error
	revertErr   error
	decided     shared.ID
	reviewer    string
	approved    bool
	reason      string
	reverted    shared.ID
	listState   rdom.State
}

func (f *fakeResponseSvc) DryRun(action rdom.Action) ([]responseuc.PlanStep, error) {
	return []responseuc.PlanStep{
		{Label: "apply " + string(action.Kind), Argv: action.Argv, BlastRadius: action.BlastRadius},
		{Label: "reverse via " + string(action.Reversal.Kind), Argv: action.Reversal.Argv, BlastRadius: action.BlastRadius},
	}, nil
}

func (f *fakeResponseSvc) Apply(_ context.Context, _ shared.ID, action rdom.Action, target engagement.Target, fingerprint responsesaga.TargetFingerprint, approver string) (responseuc.Record, error) {
	f.applied, f.appTarget, f.fingerprint, f.approver = action, target, fingerprint, approver
	if f.applyErr != nil {
		if f.applyErr == responseuc.ErrVerificationPending {
			return f.rec, f.applyErr
		}
		// Mirror the real service: on a pending admission the record is returned WITH the error so the
		// handler can surface the server-minted id in the 202.
		return rdom.Record{Action: action, State: rdom.StatePending, ApprovedBy: approver}, f.applyErr
	}
	return f.rec, nil
}

func (f *fakeResponseSvc) Revert(_ context.Context, id shared.ID, _ engagement.Target, _ responsesaga.TargetFingerprint, _ string) (responseuc.Record, error) {
	f.reverted = id
	return f.rec, f.revertErr
}

func (f *fakeResponseSvc) Decide(_ context.Context, id shared.ID, reviewer string, approve bool, reason string) (responseuc.Record, error) {
	f.decided, f.reviewer, f.approved, f.reason = id, reviewer, approve, reason
	return f.rec, f.decideErr
}

func (f *fakeResponseSvc) ListByState(_ context.Context, state rdom.State) ([]responseuc.Record, error) {
	f.listState = state
	return []responseuc.Record{f.rec}, nil
}

type oneID struct{ id string }

func (o oneID) NewID() shared.ID { return shared.ID(o.id) }

func responseRouter(t *testing.T) (*Router, *fakeResponseSvc) {
	t.Helper()
	rt, _, _ := newEngRouter(t) // seeds engagement "eng-1" in the default tenant
	applied, _ := rdom.NewAction(shared.ID("act-1"), rdom.KindStopProcess, shared.ID("asset-9"))
	fake := &fakeResponseSvc{rec: rdom.Record{Action: applied, State: rdom.StateApplied, ApprovedBy: "alice", Verification: rdom.VerificationSucceeded}}
	rt.SetResponse(fake, oneID{id: "act-1"})
	rt.vulnerabilityAudit = &fakeAudit{}
	return rt, fake
}

func TestPlanResponseEnumeratesApplyAndReversal(t *testing.T) {
	rt, _ := responseRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/engagements/eng-1/response/plan", strings.NewReader(`{"kind":"stop_process","target":"asset-9"}`))
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	rt.planResponse(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("plan: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Kind, Target string
		Steps        []struct {
			Label, BlastRadius string
			Argv               []string
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != "stop_process" || body.Target != "asset-9" || len(body.Steps) != 2 {
		t.Fatalf("plan body = %+v", body)
	}
	if body.Steps[0].Label != "apply stop_process" || len(body.Steps[0].Argv) == 0 {
		t.Fatalf("apply step = %+v", body.Steps[0])
	}
	if !strings.HasPrefix(body.Steps[1].Label, "reverse via") {
		t.Fatalf("reversal step = %+v", body.Steps[1])
	}
}

func TestResponseMutationBodiesAreBounded(t *testing.T) {
	for _, test := range []struct {
		name   string
		invoke func(*Router, http.ResponseWriter, *http.Request)
		path   string
	}{
		{name: "plan", invoke: (*Router).planResponse, path: "/api/v1/blueteam/engagements/eng-1/response/plan"},
		{name: "apply", invoke: (*Router).applyResponse, path: "/api/v1/blueteam/engagements/eng-1/response/apply"},
		{name: "decide", invoke: (*Router).decideResponse, path: "/api/v1/blueteam/response/act-1/decide"},
		{name: "revert", invoke: (*Router).revertResponse, path: "/api/v1/blueteam/response/act-1/revert"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt, fake := responseRouter(t)
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(strings.Repeat(" ", responseBodyLimit)+`{}`))
			request.SetPathValue("id", "eng-1")
			if test.name == "decide" || test.name == "revert" {
				request.SetPathValue("id", "act-1")
			}
			response := httptest.NewRecorder()

			test.invoke(rt, response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", response.Code, response.Body.String())
			}
			if !fake.applied.ID.IsZero() || !fake.decided.IsZero() || !fake.reverted.IsZero() {
				t.Fatalf("oversized body reached response service: %+v", fake)
			}
		})
	}
}

func TestPlanResponseRejectsUnknownKind(t *testing.T) {
	rt, _ := responseRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/engagements/eng-1/response/plan", strings.NewReader(`{"kind":"format_disk","target":"asset-9"}`))
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	rt.planResponse(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind: code=%d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestApplyResponsePassesTheServerMintedActionThroughTheGate(t *testing.T) {
	rt, fake := responseRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/engagements/eng-1/response/apply", strings.NewReader(`{"kind":"stop_process","target":"asset-9","target_kind":"ip","fingerprint":{"kind":"process","process_asset_id":"asset-9","process_entity_id":"asset-9"}}`))
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	rt.applyResponse(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: code=%d body=%s", rec.Code, rec.Body.String())
	}
	// The action id is server-minted, never taken from the client.
	if fake.applied.ID != "act-1" || fake.applied.Kind != rdom.KindStopProcess || fake.applied.Target != "asset-9" {
		t.Fatalf("applied action = %+v", fake.applied)
	}
	if fake.appTarget.Value != "asset-9" || fake.appTarget.Kind != engagement.TargetIP {
		t.Fatalf("apply target = %+v", fake.appTarget)
	}
	if fake.fingerprint.Kind != responsesaga.FingerprintProcess || fake.fingerprint.ProcessAssetID != "asset-9" || fake.fingerprint.ProcessEntityID != "asset-9" {
		t.Fatalf("apply fingerprint = %+v", fake.fingerprint)
	}
	var body responseRecordDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ID != "act-1" || body.State != "applied" || body.Approver != "alice" || body.Verification != "succeeded" {
		t.Fatalf("record body = %+v", body)
	}
}

func TestApplyResponseUnknownEngagementIs404(t *testing.T) {
	rt, _ := responseRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/engagements/nope/response/apply", strings.NewReader(`{"kind":"stop_process","target":"asset-9"}`))
	req.SetPathValue("id", "nope")
	rec := httptest.NewRecorder()
	rt.applyResponse(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown engagement: code=%d, want 404 (%s)", rec.Code, rec.Body.String())
	}
}

func TestApplyResponsePendingApprovalIs202(t *testing.T) {
	rt, fake := responseRouter(t)
	fake.applyErr = safety.ErrPendingApproval
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/engagements/eng-1/response/apply", strings.NewReader(`{"kind":"isolate_host","target":"asset-9"}`))
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	rt.applyResponse(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pending approval: code=%d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var body responseRecordDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ID != "act-1" || body.State != "pending" {
		t.Fatalf("202 body must carry the server-minted pending id: %+v", body)
	}
}

func TestApplyResponsePendingVerificationIs202(t *testing.T) {
	rt, fake := responseRouter(t)
	fake.rec.Verification = rdom.VerificationPending
	fake.applyErr = responseuc.ErrVerificationPending
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/engagements/eng-1/response/apply", strings.NewReader(`{"kind":"stop_process","target":"asset-9","target_kind":"ip","fingerprint":{"kind":"process","process_asset_id":"asset-9","process_entity_id":"asset-9"}}`))
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	rt.applyResponse(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pending verification: code=%d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var body responseRecordDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ID != "act-1" || body.Verification != "pending" {
		t.Fatalf("202 body must carry the durable response: %+v", body)
	}
}

func TestDecideResponsePassesAuthenticatedReviewerAndActionID(t *testing.T) {
	rt, fake := responseRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/response/act-1/decide", strings.NewReader(`{"approve":true,"reason":"validated target"}`))
	req.SetPathValue("id", "act-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "reviewer-1", Role: "reviewer", TenantID: "tenant-1"}))
	rec := httptest.NewRecorder()
	rt.decideResponse(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("decide: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if fake.decided != "act-1" || fake.reviewer != "reviewer-1" || !fake.approved || fake.reason != "validated target" {
		t.Fatalf("decision = id=%s reviewer=%q approve=%v reason=%q", fake.decided, fake.reviewer, fake.approved, fake.reason)
	}
}

func TestDecideResponseRequiresExplicitDecision(t *testing.T) {
	rt, fake := responseRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/response/act-1/decide", strings.NewReader(`{"reason":"missing decision"}`))
	req.SetPathValue("id", "act-1")
	rec := httptest.NewRecorder()
	rt.decideResponse(rec, req)
	if rec.Code != http.StatusBadRequest || !fake.decided.IsZero() {
		t.Fatalf("missing approve: code=%d decided=%s body=%s", rec.Code, fake.decided, rec.Body.String())
	}
}

func TestDecideResponsePendingVerificationIs202(t *testing.T) {
	rt, fake := responseRouter(t)
	fake.rec.Verification = rdom.VerificationPending
	fake.decideErr = responseuc.ErrVerificationPending
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/response/act-1/decide", strings.NewReader(`{"approve":true}`))
	req.SetPathValue("id", "act-1")
	rec := httptest.NewRecorder()
	rt.decideResponse(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pending verification: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var body responseRecordDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ID != "act-1" || body.Verification != "pending" {
		t.Fatalf("202 body must carry the durable response: %+v", body)
	}
}

func TestDecideResponseRequiresReviewPermission(t *testing.T) {
	for _, tc := range []struct {
		role string
		want int
	}{
		{role: "reviewer", want: http.StatusOK},
		{role: "consultant", want: http.StatusForbidden},
		{role: "agent", want: http.StatusForbidden},
	} {
		t.Run(tc.role, func(t *testing.T) {
			rt, fake := responseRouter(t)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/response/act-1/decide", strings.NewReader(`{"approve":false}`))
			req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "reviewer-1", Role: tc.role, TenantID: "tenant-1"}))
			rec := httptest.NewRecorder()
			rt.routes().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("role %s: code=%d want=%d body=%s", tc.role, rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusForbidden && !fake.decided.IsZero() {
				t.Fatalf("role %s reached decision service", tc.role)
			}
		})
	}
}

func TestListResponseRejectsUnknownState(t *testing.T) {
	rt, _ := responseRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/blueteam/response?state=garbage", nil)
	rec := httptest.NewRecorder()
	rt.listResponses(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown state: code=%d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestRevertAndListResponses(t *testing.T) {
	rt, fake := responseRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/response/act-1/revert", strings.NewReader(`{"target":"asset-9","fingerprint":{"kind":"process","process_asset_id":"asset-9","process_entity_id":"asset-9"}}`))
	req.SetPathValue("id", "act-1")
	rec := httptest.NewRecorder()
	rt.revertResponse(rec, req)
	if rec.Code != http.StatusOK || fake.reverted != "act-1" {
		t.Fatalf("revert: code=%d reverted=%s (%s)", rec.Code, fake.reverted, rec.Body.String())
	}

	lreq := httptest.NewRequest(http.MethodGet, "/api/v1/blueteam/response?state=pending", nil)
	lreq = lreq.WithContext(context.WithValue(lreq.Context(), principalKey, Principal{ID: "analyst", Role: "consultant"}))
	lrec := httptest.NewRecorder()
	rt.listResponses(lrec, lreq)
	if lrec.Code != http.StatusOK || fake.listState != rdom.StatePending {
		t.Fatalf("list: code=%d state=%s (%s)", lrec.Code, fake.listState, lrec.Body.String())
	}
	var body struct {
		Responses []responseRecordDTO
	}
	if err := json.Unmarshal(lrec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Responses) != 1 || body.Responses[0].ID != "act-1" {
		t.Fatalf("list body = %+v", body)
	}
}

func TestRevertResponsePendingApprovalIs202(t *testing.T) {
	rt, fake := responseRouter(t)
	fake.revertErr = safety.ErrPendingApproval
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/response/act-1/revert", strings.NewReader(`{"target":"asset-9","fingerprint":{"kind":"process","process_asset_id":"asset-9","process_entity_id":"asset-9"}}`))
	req.SetPathValue("id", "act-1")
	rec := httptest.NewRecorder()
	rt.revertResponse(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pending reversal approval: code=%d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var body responseRecordDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ID != "act-1" {
		t.Fatalf("202 body must carry the original response id: %+v", body)
	}
}
