package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	ticketuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type ticketHTTPFake struct {
	ticketWorkflow
	calls        int
	tenant       shared.ID
	mappingInput ticketuc.MappingInput
	resetInput   [4]string
}

type ticketPreviewFake struct {
	ticketHTTPFake
	preview ticketuc.Preview
}

func (f *ticketPreviewFake) Preview(context.Context, ticketuc.PreviewRequest) (ticketuc.Preview, error) {
	return f.preview, nil
}

func TestTicketPreviewDisclosesOnlyDestinationFrozenInDigestPayload(t *testing.T) {
	fake := &ticketPreviewFake{preview: ticketuc.Preview{
		Payload: []byte(`{"fields":{"project":{"key":"owner/repo"},"issuetype":{"id":"issue"}},"_synapse":{"provider":"gitlab-issues","endpoint":"https://gitlab.example","credential_revision":9,"waiver_reason":"must not leak"}}`),
		Digest:  "digest-bound-to-payload",
	}}
	rt := &Router{log: discardLog()}
	rt.SetTicketing(fake)
	request := httptest.NewRequest("POST", "/api/v1/engagements/eng/findings/finding/ticket-preview", strings.NewReader(`{"mapping_id":"mapping"}`))
	response := httptest.NewRecorder()
	rt.previewTicket(response, request)
	if response.Code != 200 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["provider"] != "gitlab-issues" || body["endpoint"] != "https://gitlab.example" || body["digest"] != "digest-bound-to-payload" {
		t.Fatalf("destination=%v", body)
	}
	if strings.Contains(response.Body.String(), "credential_revision") || strings.Contains(response.Body.String(), "waiver_reason") || strings.Contains(response.Body.String(), "_synapse") {
		t.Fatalf("internal snapshot leaked: %s", response.Body.String())
	}
}

func (f *ticketHTTPFake) ResetBreaker(_ context.Context, tenant, id shared.ID, project, issueType, actor string) error {
	f.calls++
	f.tenant = tenant
	f.resetInput = [4]string{id.String(), project, issueType, actor}
	return nil
}

func TestResetJiraBreakerRouteDerivesTenantAndActor(t *testing.T) {
	fake := &ticketHTTPFake{}
	rt := &Router{log: discardLog()}
	rt.SetTicketing(fake)
	for _, body := range []string{`{"project_key":"SEC","issue_type":"10001","tenant_id":"other"}`, `{"project_key":"SEC","issue_type":"10001","actor":"other"}`} {
		req := httptest.NewRequest("POST", "/api/v1/integrations/jira/jira-breaker/reset", strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "admin-id", Role: "admin", TenantID: "tenant-a"}))
		res := httptest.NewRecorder()
		rt.routes().ServeHTTP(res, req)
		if res.Code != 400 || fake.calls != 0 {
			t.Fatalf("authority injection: status=%d calls=%d", res.Code, fake.calls)
		}
	}
	req := httptest.NewRequest("POST", "/api/v1/integrations/jira/jira-breaker/reset", strings.NewReader(`{"project_key":"SEC","issue_type":"10001"}`))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "admin-id", Role: "admin", TenantID: "tenant-a"}))
	res := httptest.NewRecorder()
	rt.routes().ServeHTTP(res, req)
	if res.Code != 204 || fake.calls != 1 || fake.tenant != "tenant-a" || fake.resetInput != [4]string{"jira", "SEC", "10001", "admin-id"} {
		t.Fatalf("reset: status=%d calls=%d tenant=%s input=%+v", res.Code, fake.calls, fake.tenant, fake.resetInput)
	}
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
		{"GET", "/api/v1/integrations/forge/ticket-metadata", []string{"consultant", "reviewer", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/ticket-mappings", []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""}},
		{"PUT", "/api/v1/ticket-mappings/mapping", []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""}},
		{"DELETE", "/api/v1/ticket-mappings/mapping", []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/engagements/eng/findings/finding/tickets", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"DELETE", "/api/v1/engagements/eng/findings/finding/tickets/link", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/engagements/eng/findings/finding/ticket-submit", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/engagements/eng/tickets/bulk", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/ticket-intents/intent/reconcile", []string{"integration_admin", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/ticket-intents/intent/retry", []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""}},
		{"POST", "/api/v1/integrations/jira/jira-breaker/reset", []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""}},
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

func (f *ticketHTTPFake) Metadata(_ context.Context, tenant, integrationID shared.ID, project, typ, issue string) (ports.TicketMetadata, error) {
	f.calls++
	f.tenant = tenant
	if tenant != "tenant-a" {
		return ports.TicketMetadata{}, shared.ErrNotFound
	}
	return ports.TicketMetadata{Projects: []ports.TicketChoice{{ID: "owner/private", Name: "Private repository"}}, SecurityPolicy: "private_repository"}, nil
}
func TestTicketMetadataAliasDerivesTenantAndRequiresIntegrationPermission(t *testing.T) {
	for _, endpoint := range []string{"ticket-metadata", "jira-metadata"} {
		fake := &ticketHTTPFake{}
		rt := &Router{log: discardLog()}
		rt.SetTicketing(fake)
		for _, test := range []struct {
			tenant string
			status int
		}{{"tenant-a", 200}, {"tenant-b", 404}} {
			req := httptest.NewRequest("GET", "/api/v1/integrations/forge/"+endpoint+"?tenant_id=tenant-a", nil)
			req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "integration-user", Role: "integration_admin", TenantID: test.tenant}))
			res := httptest.NewRecorder()
			rt.routes().ServeHTTP(res, req)
			if res.Code != test.status || fake.tenant.String() != test.tenant {
				t.Fatalf("%s tenant=%s status=%d actualTenant=%s", endpoint, test.tenant, res.Code, fake.tenant)
			}
			if test.tenant != "tenant-a" && strings.Contains(res.Body.String(), "owner/private") {
				t.Fatal("foreign metadata leaked")
			}
		}
	}
}
