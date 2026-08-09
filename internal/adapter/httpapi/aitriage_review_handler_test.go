package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type aiReviewFake struct {
	listedTenant shared.ID
	filter       ports.AITriageReviewFilter
	decided      bool
	actor        string
}

func (f *aiReviewFake) List(_ context.Context, tenantID shared.ID, filter ports.AITriageReviewFilter) ([]aitriagereview.Review, error) {
	f.listedTenant, f.filter = tenantID, filter
	return []aitriagereview.Review{{ID: "r1", State: aitriagereview.StatePending}}, nil
}

func (f *aiReviewFake) Decide(_ context.Context, _, id shared.ID, actor string, decision aitriagereview.Decision, rationale string, version int) (aitriagereview.Review, error) {
	f.decided, f.actor = true, actor
	return aitriagereview.Review{ID: id, State: aitriagereview.StateAccepted, DecidedBy: actor, DecisionRationale: rationale, Version: version + 1}, nil
}

func (f *aiReviewFake) Claim(_ context.Context, _, id shared.ID, actor string, version int) (aitriagereview.Review, error) {
	f.actor = actor
	return aitriagereview.Review{ID: id, Owner: actor, State: aitriagereview.StatePending, Version: version + 1}, nil
}

func TestAITriageReviewListMapsTenantAndFilters(t *testing.T) {
	fake := &aiReviewFake{}
	rt := &Router{log: logging.New("error")}
	rt.SetAITriageReviews(fake)
	req := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/ai-triage/reviews?severity=high&cwe=CWE-89&project=p1&state=pending", nil), "reader", "readonly")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "reader", Role: "readonly", TenantID: "tenant-a"}))
	w := httptest.NewRecorder()
	rt.authz(userdom.PermView, rt.listAITriageReviews)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if fake.listedTenant != "tenant-a" || fake.filter.Severity != shared.SeverityHigh || fake.filter.CWE != "CWE-89" || fake.filter.ProjectID != "p1" || fake.filter.State != aitriagereview.StatePending {
		t.Fatalf("filters not mapped: tenant=%s filter=%+v", fake.listedTenant, fake.filter)
	}
}

func TestAITriageDecisionRBACBlocksMachineAndAttributesHuman(t *testing.T) {
	fake := &aiReviewFake{}
	rt := &Router{log: logging.New("error")}
	rt.SetAITriageReviews(fake)
	request := func(id, role string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ai-triage/reviews/r1/decision", strings.NewReader(`{"decision":"accept","rationale":"fixture only","version":1}`))
		req = withPrincipal(req, id, role)
		req.SetPathValue("rid", "r1")
		w := httptest.NewRecorder()
		rt.authz(userdom.PermReview, rt.decideAITriageReview)(w, req)
		return w
	}
	if w := request("bot", "agent"); w.Code != http.StatusForbidden || fake.decided {
		t.Fatalf("machine decision reached service: %d", w.Code)
	}
	if w := request("alice", "reviewer"); w.Code != http.StatusOK || !fake.decided || fake.actor != "alice" {
		t.Fatalf("human decision failed: status=%d actor=%q", w.Code, fake.actor)
	}
}
