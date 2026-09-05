package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/scmconnectoruc"
)

type fakeConnectors struct {
	created   scmconnectoruc.CreateInput
	list      []ports.SCMConnectorMeta
	deleted   shared.ID
	createErr error
}

func (f *fakeConnectors) Create(_ context.Context, in scmconnectoruc.CreateInput) (ports.SCMConnectorMeta, error) {
	f.created = in
	if f.createErr != nil {
		return ports.SCMConnectorMeta{}, f.createErr
	}
	return ports.SCMConnectorMeta{
		ID: "conn-1", Name: in.Name, Provider: in.Provider, Host: "github.com",
		Username: "x-access-token", AuthKind: scmconnector.AuthPAT, CreatedAt: time.Unix(0, 0).UTC(),
	}, nil
}

func (f *fakeConnectors) List(context.Context) ([]ports.SCMConnectorMeta, error) { return f.list, nil }
func (f *fakeConnectors) Delete(_ context.Context, id shared.ID) error           { f.deleted = id; return nil }

func adminReq(method, path, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	return r.WithContext(context.WithValue(r.Context(), principalKey, Principal{ID: "admin-1", Role: "admin", TenantID: "tenant-a"}))
}

func TestConnectorRoutesRegisteredOnlyWhenWired(t *testing.T) {
	rt := &Router{log: discardLog()}
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/connectors", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("connector route registered before SetConnectors: %d", rec.Code)
	}
	rt.SetConnectors(&fakeConnectors{})
	rec = httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/connectors", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("connector route missing after SetConnectors")
	}
}

func TestCreateConnectorTokenIsWriteOnly(t *testing.T) {
	svc := &fakeConnectors{}
	rt := &Router{log: discardLog(), connectors: svc}
	req := adminReq(http.MethodPost, "/api/v1/connectors",
		`{"name":"prod","provider":"github","host":"github.com","username":"x-access-token","token":"ghp_supersecret"}`)
	rec := httptest.NewRecorder()
	rt.createConnector(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	// The token reaches the service (write-only) ...
	if svc.created.Token != "ghp_supersecret" || svc.created.TenantID != "tenant-a" {
		t.Fatalf("service create input = %+v", svc.created)
	}
	// ... but never appears in the response body (no secret value, no "token" JSON key).
	if strings.Contains(rec.Body.String(), "ghp_supersecret") || strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("response must not echo the token: %s", rec.Body.String())
	}
	var dto connectorDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	if dto.ID != "conn-1" || dto.Provider != "github" {
		t.Fatalf("dto = %+v", dto)
	}
}

func TestListConnectorsOmitsToken(t *testing.T) {
	svc := &fakeConnectors{list: []ports.SCMConnectorMeta{
		{ID: "conn-1", Name: "prod", Provider: scmconnector.ProviderGitHub, Host: "github.com", Username: "x-access-token", AuthKind: scmconnector.AuthPAT},
	}}
	rt := &Router{log: discardLog(), connectors: svc}
	rec := httptest.NewRecorder()
	rt.listConnectors(rec, adminReq(http.MethodGet, "/api/v1/connectors", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("list must not carry a token field: %s", rec.Body.String())
	}
	var body struct {
		Connectors []connectorDTO `json:"connectors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Connectors) != 1 || body.Connectors[0].Host != "github.com" {
		t.Fatalf("body = %+v", body)
	}
}

func TestDeleteConnector(t *testing.T) {
	svc := &fakeConnectors{}
	rt := &Router{log: discardLog(), connectors: svc}
	req := adminReq(http.MethodDelete, "/api/v1/connectors/conn-1", "")
	req.SetPathValue("id", "conn-1")
	rec := httptest.NewRecorder()
	rt.deleteConnector(rec, req)
	if rec.Code != http.StatusNoContent || svc.deleted != "conn-1" {
		t.Fatalf("delete: code=%d deleted=%q", rec.Code, svc.deleted)
	}
}

type seqIDsH struct{ n int }

func (s *seqIDsH) NewID() shared.ID { s.n++; return shared.ID(fmt.Sprintf("conn-%d", s.n)) }

type fixedClockH struct{}

func (fixedClockH) Now() time.Time { return time.Unix(0, 0).UTC() }

// TestConnectorsAreTenantIsolatedOverHTTP drives the real store + service + handler and proves a tenant
// cannot see or delete another tenant's connector (the hostile-isolation gate CLAUDE.md requires for a
// new tenant-scoped table, at the HTTP edge).
func TestConnectorsAreTenantIsolatedOverHTTP(t *testing.T) {
	store := memory.NewSCMConnectorStore()
	svc, err := scmconnectoruc.NewService(store, &seqIDsH{}, fixedClockH{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetConnectors(svc)

	// tenant-a creates a connector.
	rec := httptest.NewRecorder()
	rt.createConnector(rec, tenantReq(http.MethodPost, "/api/v1/connectors", "tenant-a",
		`{"name":"prod","provider":"github","host":"github.com","token":"ghp_x"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}

	// tenant-b lists: sees none.
	rec = httptest.NewRecorder()
	rt.listConnectors(rec, tenantReq(http.MethodGet, "/api/v1/connectors", "tenant-b", ""))
	var body struct {
		Connectors []connectorDTO `json:"connectors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || len(body.Connectors) != 0 {
		t.Fatalf("tenant-b must see no connectors: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// tenant-b cannot delete tenant-a's connector (id conn-1): 404, and tenant-a still has it.
	dreq := tenantReq(http.MethodDelete, "/api/v1/connectors/conn-1", "tenant-b", "")
	dreq.SetPathValue("id", "conn-1")
	rec = httptest.NewRecorder()
	rt.deleteConnector(rec, dreq)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete must be 404, got %d", rec.Code)
	}
	if _, ok, _ := store.ResolveGitCredential(shared.WithTenant(context.Background(), "tenant-a"), "github.com"); !ok {
		t.Fatal("tenant-a's connector must survive a cross-tenant delete attempt")
	}
}

func tenantReq(method, path, tenant, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	return r.WithContext(context.WithValue(r.Context(), principalKey, Principal{ID: "admin", Role: "admin", TenantID: tenant}))
}
