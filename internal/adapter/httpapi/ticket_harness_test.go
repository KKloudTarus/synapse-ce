package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	ticketuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type manualTicketIntegrations struct{ ports.IntegrationStore }
type manualTicketProviders struct{}

func (manualTicketProviders) TicketProvider(context.Context, integration.Integration) (ports.TicketProvider, error) {
	return nil, shared.ErrForbidden
}

func (manualTicketProviders) TicketProviderDescriptor(integration.Provider) (integration.ProviderDescriptor, error) {
	return integration.ProviderDescriptor{}, shared.ErrForbidden
}

type manualTicketPolicy struct{}

func (manualTicketPolicy) GetEngagementNotificationSetting(context.Context, shared.ID, shared.ID) (notification.EngagementNotificationSetting, error) {
	return notification.EngagementNotificationSetting{}, shared.ErrForbidden
}

func runTicketManualHostileHarness(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	ctx := shared.WithTenant(context.Background(), "ticket-tenant")
	engagements := memory.NewEngagementRepository()
	findings := memory.NewFindingRepository()
	e, err := engdom.New("ticket-eng", "ticket-tenant", "Dedicated test", "Synapse", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = engagements.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	for _, id := range []shared.ID{"ticket-finding-a", "ticket-finding-b"} {
		f, err := finding.NewManual(id, e.ID, finding.ManualInput{Title: "Synthetic finding", Severity: shared.SeverityHigh}, now)
		if err != nil {
			t.Fatal(err)
		}
		if err = findings.Upsert(ctx, []finding.Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
	store, err := memory.NewTicketStore(engagements, findings)
	if err != nil {
		t.Fatal(err)
	}
	audit := &harnessAudit{}
	clock := fixedClock{t: now}
	ids := idgen.RandomID{}
	workflow, err := ticketuc.NewWorkflow(store, manualTicketIntegrations{}, manualTicketProviders{}, findings, engagements, manualTicketPolicy{}, audit, ids, clock)
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog(), eng: enguc.NewService(engagements, clock, ids, audit)}
	rt.SetTicketing(workflow)
	serve := func(method, path, body, tenant string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "ticket-admin", Role: "admin", TenantID: tenant}))
		res := httptest.NewRecorder()
		rt.routes().ServeHTTP(res, req)
		return res
	}
	path := "/api/v1/engagements/ticket-eng/findings/ticket-finding-a/tickets"
	for _, bad := range []string{"http://jira.example/browse/SEC-1", "https://user:password@jira.example/browse/SEC-1", "https://jira.example/browse/SEC-1?token=fixture"} {
		body, _ := json.Marshal(map[string]string{"url": bad})
		res := serve("POST", path, string(body), "ticket-tenant")
		if res.Code != 400 {
			t.Fatalf("invalid link status=%d", res.Code)
		}
	}
	res := serve("POST", path, `{"url":"https://jira.example/browse/SEC-1"}`, "ticket-tenant")
	if res.Code != 201 {
		t.Fatalf("link status=%d %s", res.Code, res.Body)
	}
	var link ticketLinkView
	if err = json.Unmarshal(res.Body.Bytes(), &link); err != nil || link.ID.IsZero() {
		t.Fatalf("link %v %v", link, err)
	}
	if res = serve("GET", path, "", "other-tenant"); res.Code != 404 || strings.Contains(res.Body.String(), "SEC-1") {
		t.Fatal("foreign tenant reached ticket")
	}
	if res = serve("DELETE", "/api/v1/engagements/ticket-eng/findings/ticket-finding-b/tickets/"+link.ID.String(), "", "ticket-tenant"); res.Code != 404 {
		t.Fatalf("wrong finding unlink=%d", res.Code)
	}
	if res = serve("GET", path, "", "ticket-tenant"); res.Code != 200 || !strings.Contains(res.Body.String(), "SEC-1") {
		t.Fatalf("owned list=%d %s", res.Code, res.Body)
	}
	if res = serve("DELETE", path+"/"+link.ID.String(), "", "ticket-tenant"); res.Code != 204 {
		t.Fatalf("unlink=%d %s", res.Code, res.Body)
	}
	if res = serve("GET", path, "", "ticket-tenant"); res.Code != 200 || strings.Contains(res.Body.String(), "SEC-1") {
		t.Fatal("unlinked ticket remains")
	}
}
