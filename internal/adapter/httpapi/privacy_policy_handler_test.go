package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	privacypolicyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/privacypolicy"
)

type privacyPolicyHTTPClock struct{ now time.Time }

func (c *privacyPolicyHTTPClock) Now() time.Time { return c.now }

func newPrivacyPolicyHTTPService(t *testing.T) (*privacypolicyuc.Service, *privacyPolicyHTTPClock) {
	t.Helper()
	clock := &privacyPolicyHTTPClock{now: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)}
	service, err := privacypolicyuc.NewService(memory.NewPrivacyPolicyStore(), ftAudit{}, clock)
	if err != nil {
		t.Fatalf("privacy policy service: %v", err)
	}
	return service, clock
}

func privacyPolicyHumanRequest(method, path, role string, tenant shared.ID, body any) *http.Request {
	var encoded bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&encoded).Encode(body)
	}
	req := httptest.NewRequest(method, path, &encoded)
	ctx := ctxAs(role)
	if !tenant.IsZero() {
		ctx = shared.WithTenant(ctx, tenant)
	}
	return req.WithContext(ctx)
}

func TestPrivacyPolicyHumanRoutesEnforceRBACAndTenantIsolation(t *testing.T) {
	service, clock := newPrivacyPolicyHTTPService(t)
	rt := &Router{log: discardLog()}
	rt.SetPrivacyPolicyService(service)
	h := rt.routes()

	firstPolicy := privacy.DefaultPolicy()
	first := newPrivacyPolicyDTO(firstPolicy)
	first.Dispositions[string(privacy.CategoryProcessArg)] = string(privacy.DispositionRedact)
	first.Dispositions[string(privacy.CategoryProcessPath)] = string(privacy.DispositionHash)
	first.Version = "tenant-a:v1"

	for _, role := range []string{"readonly", "consultant", "reviewer"} {
		t.Run("reject non-admin mutation "+role, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodPost, "/api/v1/fleet/privacy-policies", role, "tenant-a", privacyPolicyAdmissionRequest{Policy: first}))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("non-admin admission status = %d, want 403", rec.Code)
			}
		})
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodPost, "/api/v1/fleet/privacy-policies", "admin", "tenant-a", privacyPolicyAdmissionRequest{Policy: first}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin admission status = %d (%s), want 201", rec.Code, rec.Body.String())
	}
	var admitted privacyPolicyAdmissionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &admitted); err != nil {
		t.Fatalf("decode admission: %v", err)
	}
	if !admitted.Created || admitted.Assignment.TenantID != "tenant-a" || admitted.Assignment.Digest == "" {
		t.Fatalf("admission response = %#v", admitted)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodGet, "/api/v1/fleet/privacy-policies/active", "readonly", "tenant-a", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("admission changed active policy status = %d, want 404", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodPost, "/api/v1/fleet/privacy-policies/activate", "admin", "tenant-a", privacyPolicyActivationRequest{
		Digest: admitted.Assignment.Digest, OperationID: "activate-v1",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("initial activation status = %d (%s), want 200", rec.Code, rec.Body.String())
	}

	for _, path := range []string{"/api/v1/fleet/privacy-policies/active", "/api/v1/fleet/privacy-policies"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodGet, path, "readonly", "tenant-a", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("readonly GET %s status = %d (%s), want 200", path, rec.Code, rec.Body.String())
		}
	}

	second := first
	second.Version = "tenant-a:v2"
	second.MaxArgLen--
	clock.now = clock.now.Add(time.Minute)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodPost, "/api/v1/fleet/privacy-policies", "admin", "tenant-a", privacyPolicyAdmissionRequest{Policy: second}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("second admission status = %d (%s), want 201", rec.Code, rec.Body.String())
	}
	var secondAdmission privacyPolicyAdmissionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &secondAdmission); err != nil {
		t.Fatalf("decode second admission: %v", err)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodPost, "/api/v1/fleet/privacy-policies/activate", "consultant", "tenant-a", privacyPolicyActivationRequest{Digest: secondAdmission.Assignment.Digest, OperationID: "activate-v2"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin activation status = %d, want 403", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodPost, "/api/v1/fleet/privacy-policies/activate", "admin", "tenant-a", privacyPolicyActivationRequest{Digest: secondAdmission.Assignment.Digest, OperationID: "activate-v2"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin activation status = %d (%s), want 200", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodGet, "/api/v1/fleet/privacy-policies/active", "readonly", "tenant-b", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tenant-b active policy status = %d, want 404", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodGet, "/api/v1/fleet/privacy-policies", "readonly", "tenant-b", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant-b history status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var isolated privacyPolicyHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &isolated); err != nil {
		t.Fatalf("decode tenant-b history: %v", err)
	}
	if len(isolated.Assignments) != 0 {
		t.Fatalf("tenant-b history leaked assignments: %#v", isolated.Assignments)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodGet, "/api/v1/fleet/privacy-policies", "readonly", "tenant-a", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant-a history status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var history privacyPolicyHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &history); err != nil {
		t.Fatalf("decode tenant-a history: %v", err)
	}
	if len(history.Assignments) != 2 {
		t.Fatalf("tenant-a history length = %d, want 2", len(history.Assignments))
	}
}

func TestPrivacyPolicyHumanRoutesRequireServiceAndTenantContext(t *testing.T) {
	rt := &Router{log: discardLog()}
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodGet, "/api/v1/fleet/privacy-policies", "admin", "tenant-a", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unwired human privacy-policy route status = %d, want 404", rec.Code)
	}

	service, _ := newPrivacyPolicyHTTPService(t)
	rt.SetPrivacyPolicyService(service)
	rec = httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, privacyPolicyHumanRequest(http.MethodPost, "/api/v1/fleet/privacy-policies", "admin", "", privacyPolicyAdmissionRequest{Policy: newPrivacyPolicyDTO(privacy.DefaultPolicy())}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("admission without tenant status = %d (%s), want 403", rec.Code, rec.Body.String())
	}
}

func TestFleetPrivacyPolicyRouteAuthenticatesAndIsolatesTenant(t *testing.T) {
	h, agentSvc, _ := setupFleet(t)
	service, _ := newPrivacyPolicyHTTPService(t)
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, nil, func() time.Time { return time.Now().UTC() }, "")
	rt.SetFleetPrivacyPolicyReader(service)
	h = rt.fleet.handler()

	if rec := fleetCall(h, http.MethodGet, "/api/v1/fleet/privacy-policy", "", nil, true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated policy read status = %d, want 401", rec.Code)
	}

	mintAndEnrol := func(tenant shared.ID, name string) string {
		t.Helper()
		token, err := agentSvc.MintEnrolToken(context.Background(), "operator", tenant, time.Hour)
		if err != nil {
			t.Fatalf("mint enrol token for %s: %v", tenant, err)
		}
		rec := fleetCall(h, http.MethodPost, "/api/v1/fleet/enrol", token, map[string]string{"name": name, "platform": "linux"}, true)
		if rec.Code != http.StatusCreated {
			t.Fatalf("enrol %s status = %d (%s)", tenant, rec.Code, rec.Body.String())
		}
		var response struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Token == "" {
			t.Fatalf("decode enrol response for %s: %v", tenant, err)
		}
		return response.Token
	}

	tenantAToken := mintAndEnrol("tenant-a", "agent-a")
	tenantBToken := mintAndEnrol("tenant-b", "agent-b")
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	admittedPolicy, _, err := service.Admit(ctx, "operator", privacy.DefaultPolicy())
	if err != nil {
		t.Fatalf("admit tenant-a policy: %v", err)
	}
	if _, err := service.Activate(ctx, "operator", admittedPolicy.Digest, "activate-default"); err != nil {
		t.Fatalf("activate tenant-a policy: %v", err)
	}

	rec := fleetCall(h, http.MethodGet, "/api/v1/fleet/privacy-policy", tenantAToken, nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant-a agent policy status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var assignment privacyPolicyAssignmentEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &assignment); err != nil {
		t.Fatalf("decode fleet policy assignment: %v", err)
	}
	if assignment.Assignment.TenantID != "tenant-a" {
		t.Fatalf("fleet assignment tenant = %q, want tenant-a", assignment.Assignment.TenantID)
	}

	rec = fleetCall(h, http.MethodGet, "/api/v1/fleet/privacy-policy", tenantBToken, nil, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tenant-b agent policy status = %d, want 404", rec.Code)
	}

	rt.SetFleetPrivacyPolicyReader(nil)
	rec = fleetCall(h, http.MethodGet, "/api/v1/fleet/privacy-policy", tenantAToken, nil, true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired fleet policy status = %d, want 503", rec.Code)
	}
}
