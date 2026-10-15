package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	ticketuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type ticketHTTPFake struct {
	ticketWorkflow
	calls        int
	tenant       shared.ID
	mappingInput ticketuc.MappingInput
}

func (f *ticketHTTPFake) GetFindingTickets(_ context.Context, tenant, _, _ shared.ID) (ticketuc.FindingTickets, error) {
	f.calls++
	f.tenant = tenant
	return ticketuc.FindingTickets{}, nil
}
func (f *ticketHTTPFake) SaveMapping(_ context.Context, tenant, id shared.ID, input ticketuc.MappingInput) (ticketing.Mapping, error) {
	f.calls++
	f.tenant = tenant
	f.mappingInput = input
	return ticketing.Mapping{}, shared.ErrValidation
}

func TestTicketRoutesRejectUnauthorizedHumansAndMachines(t *testing.T) {
	rt := &Router{log: discardLog()}
	rt.SetTicketing(&ticketHTTPFake{})
	cases := []struct {
		method, path string
		roles        []string
	}{
		{"POST", "/api/v1/ticket-mappings", []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""}},
		{"PUT", "/api/v1/ticket-mappings/mapping", []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""}},
		{"DELETE", "/api/v1/ticket-mappings/mapping", []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/engagements/eng/findings/finding/tickets", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"DELETE", "/api/v1/engagements/eng/findings/finding/tickets/link", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/engagements/eng/findings/finding/ticket-submit", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/engagements/eng/tickets/bulk", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/ticket-intents/intent/reconcile", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/ticket-intents/intent/retry", []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""}},
		{"GET", "/api/v1/engagements/eng/findings/finding/tickets", []string{"agent", "mcp", ""}},
		{"POST", "/api/v1/engagements/eng/findings/finding/ticket-preview", []string{"agent", "mcp", ""}},
	}
	for _, c := range cases {
		for _, role := range c.roles {
			t.Run(c.method+c.path+role, func(t *testing.T) {
				res := serveAs(rt, c.method, c.path, role)
				if res.Code != wantDenied(role) {
					t.Fatalf("status=%d want=%d", res.Code, wantDenied(role))
				}
			})
		}
	}
}

func TestFindingTicketRouteKeepsForeignEngagementHidden(t *testing.T) {
	repo := newEngRepoFake()
	svc := enguc.NewService(repo, fixedClock{t: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)}, engIDs{}, &fakeAudit{})
	if _, err := svc.Create(context.Background(), enguc.CreateInput{TenantID: "tenant-a", Name: "Test", Client: "Test"}); err != nil {
		t.Fatal(err)
	}
	fake := &ticketHTTPFake{}
	rt := &Router{log: discardLog(), eng: svc}
	rt.SetTicketing(fake)
	for _, tc := range []struct {
		tenant      string
		code, calls int
	}{{"foreign", 404, 0}, {"tenant-a", 200, 1}} {
		request := httptest.NewRequest("GET", "/api/v1/engagements/eng-1/findings/finding/tickets", nil)
		request = request.WithContext(context.WithValue(request.Context(), principalKey, Principal{ID: "reader", Role: "readonly", TenantID: tc.tenant}))
		res := httptest.NewRecorder()
		rt.routes().ServeHTTP(res, request)
		if res.Code != tc.code || fake.calls != tc.calls {
			t.Fatalf("tenant=%s status=%d calls=%d", tc.tenant, res.Code, fake.calls)
		}
		if strings.Contains(res.Body.String(), "Snapshot") || strings.Contains(res.Body.String(), "TenantID") {
			t.Fatal("internal state leaked")
		}
	}
}

func TestMappingRouteDerivesAuthorityAndRejectsAuthorityFields(t *testing.T) {
	fake := &ticketHTTPFake{}
	rt := &Router{log: discardLog()}
	rt.SetTicketing(fake)
	for _, tc := range []struct {
		body          string
		status, calls int
	}{{`{"allow_admin":true}`, 400, 0}, {`{"actor":"other"}`, 400, 0}, {`{"integration_id":"jira","scope":"engagement","scope_id":"eng","project_key":"SEC","issue_type":"100","waiver_reason":"Dedicated synthetic test"}`, 400, 1}} {
		req := httptest.NewRequest("POST", "/api/v1/ticket-mappings", strings.NewReader(tc.body))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "human-admin", Role: "admin", TenantID: "tenant"}))
		res := httptest.NewRecorder()
		rt.routes().ServeHTTP(res, req)
		if res.Code != tc.status || fake.calls != tc.calls {
			t.Fatalf("status=%d calls=%d", res.Code, fake.calls)
		}
	}
	if fake.mappingInput.Actor != "human-admin" || !fake.mappingInput.AllowAdmin || fake.tenant != "tenant" {
		t.Fatal("authority did not derive from principal")
	}
}
