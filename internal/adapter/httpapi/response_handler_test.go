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
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	responseuc "github.com/KKloudTarus/synapse-ce/internal/usecase/response"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

type fakeResponseSvc struct {
	applied   rdom.Action
	appTarget engagement.Target
	approver  string
	rec       rdom.Record
	applyErr  error
	reverted  shared.ID
	listState rdom.State
}

func (f *fakeResponseSvc) DryRun(action rdom.Action) ([]responseuc.PlanStep, error) {
	return []responseuc.PlanStep{
		{Label: "apply " + string(action.Kind), Argv: action.Argv, BlastRadius: action.BlastRadius},
		{Label: "reverse via " + string(action.Reversal.Kind), Argv: action.Reversal.Argv, BlastRadius: action.BlastRadius},
	}, nil
}

func (f *fakeResponseSvc) Apply(_ context.Context, _ shared.ID, action rdom.Action, target engagement.Target, approver string) (responseuc.Record, error) {
	f.applied, f.appTarget, f.approver = action, target, approver
	if f.applyErr != nil {
		return responseuc.Record{}, f.applyErr
	}
	return f.rec, nil
}

func (f *fakeResponseSvc) Revert(_ context.Context, id shared.ID, _ engagement.Target, _ string) (responseuc.Record, error) {
	f.reverted = id
	return f.rec, nil
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/engagements/eng-1/response/apply", strings.NewReader(`{"kind":"stop_process","target":"asset-9","target_kind":"ip"}`))
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
}

func TestRevertAndListResponses(t *testing.T) {
	rt, fake := responseRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/blueteam/response/act-1/revert", strings.NewReader(`{"target":"asset-9"}`))
	req.SetPathValue("id", "act-1")
	rec := httptest.NewRecorder()
	rt.revertResponse(rec, req)
	if rec.Code != http.StatusOK || fake.reverted != "act-1" {
		t.Fatalf("revert: code=%d reverted=%s (%s)", rec.Code, fake.reverted, rec.Body.String())
	}

	lreq := httptest.NewRequest(http.MethodGet, "/api/v1/blueteam/response?state=pending", nil)
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
