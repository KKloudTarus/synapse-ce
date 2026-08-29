package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
)

type provenanceReaderRequest struct {
	engagementID shared.ID
	detectionID  shared.ID
	tenantID     shared.ID
}

type provenanceReaderFake struct {
	current     []detectionprovenance.Current
	transitions []detectionprovenance.Transition

	listRequests       []provenanceReaderRequest
	transitionRequests []provenanceReaderRequest

	listCalls       int
	transitionCalls int
}

func (f *provenanceReaderFake) ListDetectionProvenance(ctx context.Context, engagementID shared.ID) ([]detectionprovenance.Current, error) {
	tenantID, _ := shared.TenantFrom(ctx)
	f.listRequests = append(f.listRequests, provenanceReaderRequest{engagementID: engagementID, tenantID: tenantID})
	f.listCalls++
	return f.current, nil
}

func (f *provenanceReaderFake) DetectionProvenanceTransitions(ctx context.Context, engagementID, detectionID shared.ID) ([]detectionprovenance.Transition, error) {
	tenantID, _ := shared.TenantFrom(ctx)
	f.transitionRequests = append(f.transitionRequests, provenanceReaderRequest{engagementID: engagementID, detectionID: detectionID, tenantID: tenantID})
	f.transitionCalls++
	return f.transitions, nil
}

func TestDetectionProvenanceRoutes(t *testing.T) {
	engRepo := newEngRepoFake()
	if err := engRepo.Create(context.Background(), &engdom.Engagement{
		ID: "engA", TenantID: "tenantA", Name: "A", Client: "A", Status: engdom.StatusActive,
	}); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}

	reader := &provenanceReaderFake{
		current: []detectionprovenance.Current{
			{TenantID: "tenantA", EngagementID: "engA", DetectionID: "det-1", Status: detectionprovenance.StatusComplete, EvidenceID: "ev-1", PendingInput: []byte("pending-1"), UpdatedAt: time.Unix(5, 0).UTC()},
			{TenantID: "tenantA", EngagementID: "engA", DetectionID: "det-2", Status: detectionprovenance.StatusPending, PendingInput: []byte("pending-2"), UpdatedAt: time.Unix(4, 0).UTC()},
		},
		transitions: []detectionprovenance.Transition{
			{TenantID: "tenantA", EngagementID: "engA", DetectionID: "det-1", Sequence: 1, Kind: detectionprovenance.Received, Status: detectionprovenance.StatusPending, AgentID: "agent-1", AssetID: "asset-1", TelemetryRefs: []fleetagent.TelemetryReference{{StreamID: "stream-1", Epoch: 1, Sequence: 1, EventID: "event-1", Digest: "digest-1"}}, OccurredAt: time.Unix(1, 0).UTC()},
			{TenantID: "tenantA", EngagementID: "engA", DetectionID: "det-1", Sequence: 2, Kind: detectionprovenance.TelemetryDurable, Status: detectionprovenance.StatusPending, OccurredAt: time.Unix(2, 0).UTC()},
			{TenantID: "tenantA", EngagementID: "engA", DetectionID: "det-1", Sequence: 3, Kind: detectionprovenance.CommitmentPending, Status: detectionprovenance.StatusPending, OccurredAt: time.Unix(3, 0).UTC()},
			{TenantID: "tenantA", EngagementID: "engA", DetectionID: "det-1", Sequence: 4, Kind: detectionprovenance.CommitmentSealed, Status: detectionprovenance.StatusPending, EvidenceID: "ev-1", OccurredAt: time.Unix(4, 0).UTC()},
			{TenantID: "tenantA", EngagementID: "engA", DetectionID: "det-1", Sequence: 5, Kind: detectionprovenance.Acknowledged, Status: detectionprovenance.StatusComplete, EvidenceID: "ev-1", OccurredAt: time.Unix(5, 0).UTC()},
		},
	}
	for _, current := range reader.current {
		if err := current.Validate(); err != nil {
			t.Fatalf("invalid current fixture: %v", err)
		}
	}
	for _, transition := range reader.transitions {
		if err := transition.Validate(); err != nil {
			t.Fatalf("invalid transition fixture: %v", err)
		}
	}

	aupStore := newFakeAUPStore()
	aupStore.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	auth := NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
		switch token {
		case "viewer":
			return Principal{ID: "viewer", Role: "readonly", TenantID: "tenantA"}, true
		case "no-view":
			return Principal{ID: "agent", Role: "agent", TenantID: "tenantA"}, true
		case "other-tenant":
			return Principal{ID: "consultant", Role: "consultant", TenantID: "tenantB"}, true
		default:
			return Principal{}, false
		}
	})
	rt := &Router{
		log:  discardLog(),
		auth: auth,
		aup:  newTestAUP(aupStore, &fakeAudit{}),
		eng:  enguc.NewService(engRepo, fixedClock{}, engIDs{}, &fakeAudit{}),
	}
	rt.SetDetectionProvenanceReader(reader)
	h := rt.Handler()

	call := func(token, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	list := call("viewer", "/api/v1/engagements/engA/detection-provenance")
	if list.Code != http.StatusOK {
		t.Fatalf("same-tenant list status=%d body=%s", list.Code, list.Body.String())
	}
	var listBody struct {
		Provenance []detectionprovenance.Current `json:"provenance"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode provenance list: %v", err)
	}
	if len(listBody.Provenance) != 2 || listBody.Provenance[0].DetectionID != "det-1" || listBody.Provenance[1].DetectionID != "det-2" {
		t.Fatalf("provenance list=%+v, want reader order det-1 then det-2", listBody.Provenance)
	}
	if len(reader.listRequests) != 1 || reader.listRequests[0] != (provenanceReaderRequest{engagementID: "engA", tenantID: "tenantA"}) {
		t.Fatalf("list reader requests=%+v, want exact engagement and tenant pass-through", reader.listRequests)
	}

	transitions := call("viewer", "/api/v1/engagements/engA/detections/det-1/provenance")
	if transitions.Code != http.StatusOK {
		t.Fatalf("same-tenant transitions status=%d body=%s", transitions.Code, transitions.Body.String())
	}
	var transitionsBody struct {
		Transitions []detectionprovenance.Transition `json:"transitions"`
	}
	if err := json.Unmarshal(transitions.Body.Bytes(), &transitionsBody); err != nil {
		t.Fatalf("decode provenance transitions: %v", err)
	}
	if len(transitionsBody.Transitions) != 5 {
		t.Fatalf("transitions=%+v, want complete five-fact lifecycle", transitionsBody.Transitions)
	}
	for i, transition := range transitionsBody.Transitions {
		if transition.Sequence != uint64(i+1) {
			t.Fatalf("transitions=%+v, want exact reader order sequences 1 through 5", transitionsBody.Transitions)
		}
	}
	if len(reader.transitionRequests) != 1 || reader.transitionRequests[0] != (provenanceReaderRequest{engagementID: "engA", detectionID: "det-1", tenantID: "tenantA"}) {
		t.Fatalf("transition reader requests=%+v, want exact engagement, detection, and tenant pass-through", reader.transitionRequests)
	}

	for _, route := range []struct {
		name string
		path string
	}{
		{name: "list", path: "/api/v1/engagements/engA/detection-provenance"},
		{name: "transitions", path: "/api/v1/engagements/engA/detections/det-1/provenance"},
	} {
		t.Run(route.name+"/blocked", func(t *testing.T) {
			for _, denied := range []struct {
				name  string
				token string
				want  int
			}{
				{name: "unauthenticated", want: http.StatusUnauthorized},
				{name: "without-view", token: "no-view", want: http.StatusForbidden},
				{name: "cross-tenant", token: "other-tenant", want: http.StatusNotFound},
			} {
				t.Run(denied.name, func(t *testing.T) {
					beforeListCalls, beforeTransitionCalls := reader.listCalls, reader.transitionCalls
					rec := call(denied.token, route.path)
					if rec.Code != denied.want {
						t.Errorf("%s status=%d body=%s, want %d", route.name, rec.Code, rec.Body.String(), denied.want)
					}
					if reader.listCalls != beforeListCalls || reader.transitionCalls != beforeTransitionCalls {
						t.Errorf("blocked %s request reached reader: list=%d transitions=%d, want unchanged list=%d transitions=%d", route.name, reader.listCalls, reader.transitionCalls, beforeListCalls, beforeTransitionCalls)
					}
				})
			}
		})
	}
}

func TestDetectionProvenanceRoutesAreAbsentWhenReaderUnwired(t *testing.T) {
	aupStore := newFakeAUPStore()
	aupStore.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	rt := &Router{
		log: discardLog(),
		auth: NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
			return Principal{ID: "viewer", Role: "readonly", TenantID: "tenantA"}, token == "viewer"
		}),
		aup: newTestAUP(aupStore, &fakeAudit{}),
	}

	for _, route := range []struct {
		name string
		path string
	}{
		{name: "list", path: "/api/v1/engagements/engA/detection-provenance"},
		{name: "transitions", path: "/api/v1/engagements/engA/detections/det-1/provenance"},
	} {
		t.Run(route.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route.path, nil)
			req.Header.Set("Authorization", "Bearer viewer")
			rec := httptest.NewRecorder()
			rt.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("unwired provenance %s status=%d body=%s, want 404", route.name, rec.Code, rec.Body.String())
			}
		})
	}
}
