package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	documentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/docpublish"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	ticketuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

// documentEgressPublicationHarness is a tenant-aware service double. It models the
// durable lookup that precedes any provider use: a foreign tenant returns
// not-found before the remote provider can be selected or called.
type documentEgressPublicationHarness struct {
	remoteCalls int
}

func (s *documentEgressPublicationHarness) own(tenant shared.ID) error {
	if tenant != "tenantA" {
		return shared.ErrNotFound
	}
	return nil
}

func (s *documentEgressPublicationHarness) Publish(_ context.Context, tenant shared.ID, _ ports.DocumentActor, _ documentuc.PublishInput) (documentuc.ReleaseResult, error) {
	if err := s.own(tenant); err != nil {
		return documentuc.ReleaseResult{}, err
	}
	return documentuc.ReleaseResult{Intent: &docpublish.Intent{ID: "intentA", TenantID: tenant, Action: docpublish.Create, State: writeintent.Pending, Version: 1}}, nil
}

func (s *documentEgressPublicationHarness) Unpublish(_ context.Context, tenant shared.ID, _ ports.DocumentActor, id shared.ID, _ string) (documentuc.ReleaseResult, error) {
	if err := s.own(tenant); err != nil {
		return documentuc.ReleaseResult{}, err
	}
	return documentuc.ReleaseResult{Intent: &docpublish.Intent{ID: "purgeA", TenantID: tenant, LinkID: id, Action: docpublish.Purge, State: writeintent.Pending, Version: 1}}, nil
}

func (s *documentEgressPublicationHarness) ResumePreparedPublication(_ context.Context, tenant shared.ID, _ ports.DocumentActor, id shared.ID, version int) (docpublish.Intent, error) {
	if err := s.own(tenant); err != nil {
		return docpublish.Intent{}, err
	}
	// A resumed prepared publication is the only admission endpoint here that
	// reads the provider. Keep that call after the ownership lookup so a foreign
	// intent cannot use this route as either an egress trigger or an oracle.
	s.remoteCalls++
	return docpublish.Intent{ID: id, TenantID: tenant, Action: docpublish.Create, State: writeintent.Pending, Version: version + 1}, nil
}

func (s *documentEgressPublicationHarness) Links(_ context.Context, tenant shared.ID, _ docpublish.Scope, _ shared.ID) ([]docpublish.Link, error) {
	if err := s.own(tenant); err != nil {
		return nil, err
	}
	return []docpublish.Link{}, nil
}

func (s *documentEgressPublicationHarness) Intent(_ context.Context, tenant, id shared.ID) (docpublish.Intent, error) {
	if err := s.own(tenant); err != nil {
		return docpublish.Intent{}, err
	}
	return docpublish.Intent{ID: id, TenantID: tenant, Action: docpublish.Create, State: writeintent.Pending, Version: 1}, nil
}

// documentEgressScheduleHarness keeps the same pre-egress tenant fence for every
// schedule endpoint. The handler's role is to derive identity; ownership and
// all remote side effects stay behind this tenant-scoped use-case boundary.
type documentEgressScheduleHarness struct{}

func (s *documentEgressScheduleHarness) own(tenant shared.ID) error {
	if tenant != "tenantA" {
		return shared.ErrNotFound
	}
	return nil
}

func (s *documentEgressScheduleHarness) SaveSchedule(_ context.Context, tenant shared.ID, _ ports.DocumentActor, in documentuc.ScheduleInput) (docpublish.Schedule, error) {
	if err := s.own(tenant); err != nil {
		return docpublish.Schedule{}, err
	}
	return docpublish.Schedule{ID: in.ID, TenantID: tenant, Source: in.Source, Destination: in.Destination, Enabled: in.Enabled, Version: 1}, nil
}

func (s *documentEgressScheduleHarness) ListSchedules(_ context.Context, tenant shared.ID, _ docpublish.Scope, _ shared.ID) ([]docpublish.Schedule, error) {
	if err := s.own(tenant); err != nil {
		return nil, err
	}
	return []docpublish.Schedule{}, nil
}

func (s *documentEgressScheduleHarness) DeleteSchedule(_ context.Context, tenant shared.ID, _ ports.DocumentActor, _ shared.ID, _ int) error {
	return s.own(tenant)
}

func (s *documentEgressScheduleHarness) EmailDestinations(_ context.Context, tenant shared.ID, _ ports.DocumentActor) ([]documentuc.ScheduleEmailDestination, error) {
	if err := s.own(tenant); err != nil {
		return nil, err
	}
	return []documentuc.ScheduleEmailDestination{}, nil
}

type documentEgressScheduleHistoryHarness struct{}

func (s *documentEgressScheduleHistoryHarness) RunHistory(_ context.Context, tenant, _ shared.ID) ([]ports.DocumentScheduleRunView, error) {
	if tenant != "tenantA" {
		return nil, shared.ErrNotFound
	}
	return []ports.DocumentScheduleRunView{}, nil
}

type jiraInboundWebhookHarness struct{}

func (s *jiraInboundWebhookHarness) ConfigureInboundWebhook(_ context.Context, tenant, _ shared.ID, _, _ string) (ticketuc.WebhookConfiguration, error) {
	if tenant != "tenantA" {
		return ticketuc.WebhookConfiguration{}, shared.ErrNotFound
	}
	return ticketuc.WebhookConfiguration{Path: "/api/v1/hooks/redacted", Version: 1}, nil
}

// runDocumentIntegrationEgressHarness extends the authoritative route-level hostile
// harness with every document, schedule, observation and Jira webhook
// family. Calls drive the real Router route/authz/withEngTenant wiring with an
// authenticated principal. Each foreign request is rejected without reaching a
// remote provider boundary; tenant-A controls ensure a missing route cannot
// make the suite pass vacuously.
func runDocumentIntegrationEgressHarness(t *testing.T) {
	engagements := newEngRepoFake()
	engSvc := enguc.NewService(engagements, fixedClock{t: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)}, engIDs{}, &fakeAudit{})
	if _, err := engSvc.Create(context.Background(), enguc.CreateInput{TenantID: "tenantA", Name: "Tenant A", Client: "A"}); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	publication := &documentEgressPublicationHarness{}
	schedules := &documentEgressScheduleHarness{}
	history := &documentEgressScheduleHistoryHarness{}
	observations := &observationHTTPFake{}
	jiraAdmin := &jiraInboundWebhookHarness{}
	rt := &Router{log: discardLog(), eng: engSvc, documentPublishing: publication, jiraWebhookAdmin: jiraAdmin}
	rt.SetDocumentScheduling(schedules, documentScheduleHTTPIDs{})
	rt.SetDocumentScheduleHistory(history)
	rt.SetTicketing(observations)
	mux := rt.routes()

	send := func(tenant, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "reviewer", Role: "reviewer", TenantID: tenant}))
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		return out
	}

	cases := []struct {
		name, method, path, body string
	}{
		{"publish", http.MethodPost, "/api/v1/document-publications", `{"integration_id":"connectionA","source_kind":"engagement_report","scope_id":"eng-1","source_ref":"engagement:eng-1","request_key":"publish-A"}`},
		{"intent", http.MethodGet, "/api/v1/document-publications/intentA", ""},
		{"resume", http.MethodPost, "/api/v1/document-publications/intentA/resume", `{"version":1}`},
		{"unpublish", http.MethodDelete, "/api/v1/document-links/linkA", `{"request_key":"purge-A"}`},
		{"save schedule", http.MethodPost, "/api/v1/document-schedules", `{"source_kind":"engagement_report","source_ref":"engagement:eng-1","scope_id":"eng-1","destination":"confluence","integration_id":"connectionA","timezone":"UTC","frequency":"weekly","weekday":0,"hour":9,"minute":0,"enabled":true}`},
		{"list schedules", http.MethodGet, "/api/v1/document-schedules?scope=engagement&scope_id=eng-1", ""},
		{"disable schedule", http.MethodDelete, "/api/v1/document-schedules/scheduleA", `{"expected_version":1}`},
		{"schedule runs", http.MethodGet, "/api/v1/document-schedules/scheduleA/runs", ""},
		{"email destinations", http.MethodGet, "/api/v1/document-schedules/email-destinations", ""},
		{"ticket observations", http.MethodGet, "/api/v1/engagements/eng-1/findings/finding/ticket-observations", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if out := send("tenantB", tc.method, tc.path, tc.body); out.Code != http.StatusNotFound {
				t.Fatalf("foreign status=%d body=%s", out.Code, out.Body.String())
			}
			if out := send("tenantA", tc.method, tc.path, tc.body); out.Code < 200 || out.Code >= 300 {
				t.Fatalf("owner status=%d body=%s", out.Code, out.Body.String())
			}
		})
	}
	if publication.remoteCalls != 1 {
		t.Fatalf("owner resume did not reach its provider verification boundary: calls=%d", publication.remoteCalls)
	}

	// A Jira callback determines its tenant only from the signed endpoint. A
	// body attempt to override that identity remains tenant-A; a signed request
	// for tenant-A cannot be replayed to tenant-B's endpoint.
	hook, store, receiver, _ := setupHook(t)
	endpoint := store.records[hookIDA]
	endpoint.Provider = "jira-cloud"
	store.records[hookIDA] = endpoint
	body := []byte(`{"webhookEvent":"jira:issue_updated","tenant_id":"tenant-B"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+hookIDA, strings.NewReader(string(body)))
	request.Header.Set(jiraSignatureHeader, webhookSig(hookSecret('a'), body))
	request.Header.Set("X-Atlassian-Webhook-Identifier", "tenant-fence")
	accepted := httptest.NewRecorder()
	hook.ServeHTTP(accepted, request)
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("jira callback status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	seen := receiver.snapshot()
	if len(seen) != 1 || seen[0].tenant != "tenant-A" {
		t.Fatalf("jira callback crossed tenant: %#v", seen)
	}
	replay := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+hookIDB, strings.NewReader(string(body)))
	replay.Header.Set(jiraSignatureHeader, webhookSig(hookSecret('a'), body))
	replay.Header.Set("X-Atlassian-Webhook-Identifier", "tenant-fence")
	denied := httptest.NewRecorder()
	hook.ServeHTTP(denied, replay)
	if denied.Code != http.StatusUnauthorized || len(receiver.snapshot()) != 1 {
		t.Fatalf("cross-tenant Jira replay status=%d received=%#v", denied.Code, receiver.snapshot())
	}
}
