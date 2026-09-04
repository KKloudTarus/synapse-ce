package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	integrationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/integrations"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type integrationHTTPAudit struct{}

func (integrationHTTPAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type integrationHTTPAdapter struct {
	descriptor integration.ProviderDescriptor
}

func (adapter integrationHTTPAdapter) Descriptor() integration.ProviderDescriptor {
	return adapter.descriptor
}

func newIntegrationHTTPRouter(t *testing.T) *Router {
	t.Helper()
	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}
	queue := memory.NewJobQueue(ids, clock.Now)
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	descriptor := integration.ProviderDescriptor{
		Provider: "fake-ci", Name: "Fake CI", Capabilities: []integration.Capability{integration.CapabilityTestConnection},
		SecretFields: []integration.FieldDescriptor{{Name: "token", Label: "Token", Kind: integration.FieldPassword, Required: true}},
	}
	registry := integration.NewRegistry()
	if err := registry.Register(descriptor, func(integration.Integration, integration.CredentialBundle) (integration.Adapter, error) {
		return integrationHTTPAdapter{descriptor: descriptor}, nil
	}); err != nil {
		t.Fatal(err)
	}
	audit := integrationHTTPAudit{}
	service, err := integrationuc.NewService(
		memory.NewIntegrationStore(queue, cipher, clock, audit), registry, memory.NewProjectRepository(),
		memory.MissingIntegrationAnalysisMatcher{}, ids, clock, audit,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.SetRunLock(memory.NewRunLock())
	return &Router{log: slog.Default(), integrations: service}
}

func integrationHTTPRequest(method, target, body, role, tenant string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	return request.WithContext(context.WithValue(request.Context(), principalKey, Principal{ID: "user-1", Role: role, TenantID: tenant}))
}

func TestIntegrationRoutesUseViewAndAdministerRBAC(t *testing.T) {
	router := &Router{log: slog.Default()}
	tests := []struct {
		name       string
		role       user.Role
		permission user.Permission
		wantStatus int
	}{
		{name: "readonly can view", role: user.RoleReadOnly, permission: user.PermView, wantStatus: http.StatusNoContent},
		{name: "readonly cannot administer", role: user.RoleReadOnly, permission: user.PermAdminister, wantStatus: http.StatusForbidden},
		{name: "consultant cannot administer", role: user.RoleConsultant, permission: user.PermAdminister, wantStatus: http.StatusForbidden},
		{name: "admin can administer", role: user.RoleAdmin, permission: user.PermAdminister, wantStatus: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := router.authz(test.permission, func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) })
			request := httptest.NewRequest(http.MethodGet, "/api/v1/integrations", nil)
			request = request.WithContext(context.WithValue(request.Context(), principalKey, Principal{ID: "user-1", Role: string(test.role), TenantID: "tenant-1"}))
			response := httptest.NewRecorder()
			handler(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if called != (test.wantStatus == http.StatusNoContent) {
				t.Fatalf("handler called=%v", called)
			}
		})
	}
}

func TestDecodeIntegrationJSONRejectsUnknownTrailingAndOversizedInput(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"unexpected":true}`,
		`{"version":1}{"version":2}`,
		`{"value":"` + strings.Repeat("x", (1<<20)+1) + `"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		response := httptest.NewRecorder()
		var target struct {
			Version int `json:"version"`
		}
		if decodeIntegrationJSON(response, request, &target) {
			t.Fatalf("accepted invalid body prefix %q", body[:min(len(body), 80)])
		}
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestIntegrationResponseNeverContainsCredentialPlaintext(t *testing.T) {
	item := integration.Integration{
		ID: "integration-1", TenantID: "tenant-1", Provider: "jenkins", Name: "Jenkins", Endpoint: "https://jenkins.example.com",
		Config: []byte(`{}`), PollInterval: time.Minute, Version: 1, CredentialConfigured: true,
		CreatedAt: time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC),
	}
	encoded, err := json.Marshal(integrationResponse(item))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("secret-token"), []byte("api_token"), []byte("username"), []byte("ciphertext")} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, encoded)
		}
	}
	if !bytes.Contains(encoded, []byte(`"credential_configured":true`)) {
		t.Fatalf("response omitted credential presence: %s", encoded)
	}
}

func TestIntegrationHTTPWorkflowEnforcesRBACIsolationAndSecretRedaction(t *testing.T) {
	router := newIntegrationHTTPRouter(t)
	handler := router.routes()
	createBody := `{"provider":"fake-ci","name":"Production CI","endpoint":"https://ci.example.com","config":{},"allow_private_network":false,"poll_interval_seconds":60}`

	forbidden := httptest.NewRecorder()
	handler.ServeHTTP(forbidden, integrationHTTPRequest(http.MethodPost, "/api/v1/integrations", createBody, string(user.RoleReadOnly), "tenant-a"))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("readonly create status=%d body=%s", forbidden.Code, forbidden.Body.String())
	}

	createdResponse := httptest.NewRecorder()
	handler.ServeHTTP(createdResponse, integrationHTTPRequest(http.MethodPost, "/api/v1/integrations", createBody, string(user.RoleAdmin), "tenant-a"))
	var created integrationDTO
	if createdResponse.Code != http.StatusCreated || json.Unmarshal(createdResponse.Body.Bytes(), &created) != nil || created.ID.IsZero() {
		t.Fatalf("create status=%d body=%s", createdResponse.Code, createdResponse.Body.String())
	}

	credentialResponse := httptest.NewRecorder()
	handler.ServeHTTP(credentialResponse, integrationHTTPRequest(http.MethodPut, "/api/v1/integrations/"+created.ID.String()+"/credentials", `{"secrets":{"token":"secret-token"}}`, string(user.RoleAdmin), "tenant-a"))
	if credentialResponse.Code != http.StatusNoContent {
		t.Fatalf("credential status=%d body=%s", credentialResponse.Code, credentialResponse.Body.String())
	}

	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, integrationHTTPRequest(http.MethodGet, "/api/v1/integrations/"+created.ID.String(), "", string(user.RoleReadOnly), "tenant-a"))
	var got integrationDTO
	if getResponse.Code != http.StatusOK || json.Unmarshal(getResponse.Body.Bytes(), &got) != nil || !got.CredentialConfigured {
		t.Fatalf("get status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
	for _, forbiddenValue := range []string{"secret-token", `"secrets"`, `"token"`, "ciphertext"} {
		if strings.Contains(getResponse.Body.String(), forbiddenValue) {
			t.Fatalf("integration response leaked %q: %s", forbiddenValue, getResponse.Body.String())
		}
	}

	crossTenant := httptest.NewRecorder()
	handler.ServeHTTP(crossTenant, integrationHTTPRequest(http.MethodGet, "/api/v1/integrations/"+created.ID.String(), "", string(user.RoleReadOnly), "tenant-b"))
	if crossTenant.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get status=%d body=%s", crossTenant.Code, crossTenant.Body.String())
	}
}
