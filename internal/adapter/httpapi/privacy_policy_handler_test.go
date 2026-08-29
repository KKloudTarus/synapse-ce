package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	// Build the REQUEST body with the agent-plane renderer, which keeps HashSalt: the salt
	// is still accepted on admission input (a hash disposition is invalid without one) —
	// only the human-plane RESPONSE omits it. Using the human renderer here would produce
	// a saltless policy and fail validation for a reason unrelated to what this test covers.
	first := newAgentPrivacyPolicyDTO(firstPolicy)
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

// TestPrivacyPolicyHashSaltNeverLeavesTheAgentPlane pins the Rule 3 boundary: HashSalt is
// what makes DispositionHash pseudonymization resistant to dictionary attacks over
// low-entropy telemetry, so a human principal who can read hashed telemetry must not be
// able to learn it. The agent plane still receives it, because agents hash at the source.
//
// The assertion is on the RAW JSON, not the decoded struct: hash_salt is `omitempty`, so a
// decoded struct reads "" whether the field was omitted or present-and-empty. Only the wire
// bytes prove the salt never reached the client.
func TestPrivacyPolicyHashSaltNeverLeavesTheAgentPlane(t *testing.T) {
	const salt = "sentinel-redaction-salt"
	policy := privacy.DefaultPolicy()
	policy.HashSalt = salt
	policy.Dispositions[privacy.CategoryProcessPath] = privacy.DispositionHash
	policy.Version = "tenant-a:salted"

	// saltedEchoDTO renders a DISTINCT salted policy — its own version AND its own content,
	// because the digest is derived from content alone: a version-only change still collides
	// on digest. The salt itself is unchanged, which is the point of the assertion.
	saltedEchoDTO := func(p privacy.Policy) privacyPolicyDTO {
		dto := newAgentPrivacyPolicyDTO(p)
		dto.Version = "tenant-a:salted-echo"
		dto.MaxArgLen = p.MaxArgLen - 1
		return dto
	}

	service, _ := newPrivacyPolicyHTTPService(t)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	admitted, _, err := service.Admit(ctx, "operator", policy)
	if err != nil {
		t.Fatalf("admit salted policy: %v", err)
	}
	if _, err := service.Activate(ctx, "operator", admitted.Digest, "activate-salted"); err != nil {
		t.Fatalf("activate salted policy: %v", err)
	}

	// Human plane: admission echo, active pointer, and history must all be salt-free, for
	// every role that can reach them — including the admin who authored the policy, since
	// these routes also expose policies other actors authored.
	human := &Router{log: discardLog()}
	human.SetPrivacyPolicyService(service)
	humanHandler := human.routes()
	for _, tc := range []struct {
		name, method, path, role string
		body                     any
	}{
		// A distinct version: re-admitting "tenant-a:salted" under a different actor would
		// conflict on immutable content, which is not what this case is testing.
		{"admission echo", http.MethodPost, "/api/v1/fleet/privacy-policies", "admin", privacyPolicyAdmissionRequest{Policy: saltedEchoDTO(policy)}},
		{"active as admin", http.MethodGet, "/api/v1/fleet/privacy-policies/active", "admin", nil},
		{"active as readonly", http.MethodGet, "/api/v1/fleet/privacy-policies/active", "readonly", nil},
		{"history as readonly", http.MethodGet, "/api/v1/fleet/privacy-policies", "readonly", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			humanHandler.ServeHTTP(rec, privacyPolicyHumanRequest(tc.method, tc.path, tc.role, "tenant-a", tc.body))
			if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
				t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, salt) {
				t.Fatalf("human plane leaked the redaction hash salt: %s", body)
			}
			if strings.Contains(body, "hash_salt") {
				t.Fatalf("human plane emitted a hash_salt field: %s", body)
			}
			// Sanity: the payload really is the policy, so an empty/error body cannot pass.
			if !strings.Contains(body, "max_arg_len") {
				t.Fatalf("payload does not look like a policy: %s", body)
			}
		})
	}

	// Agent plane: the salt MUST still be delivered, or source-side hashing breaks.
	t.Run("agent plane still receives the salt", func(t *testing.T) {
		fleetHandler, agentSvc, _ := setupFleet(t)
		agentRouter := &Router{log: discardLog()}
		agentRouter.SetFleet(agentSvc, nil, func() time.Time { return time.Now().UTC() }, "")
		agentRouter.SetFleetPrivacyPolicyReader(service)
		fleetHandler = agentRouter.fleet.handler()

		token, err := agentSvc.MintEnrolToken(context.Background(), "operator", "tenant-a", time.Hour)
		if err != nil {
			t.Fatalf("mint enrol token: %v", err)
		}
		rec := fleetCall(fleetHandler, http.MethodPost, "/api/v1/fleet/enrol", token, map[string]string{"name": "agent-a", "platform": "linux"}, true)
		if rec.Code != http.StatusCreated {
			t.Fatalf("enrol status = %d (%s)", rec.Code, rec.Body.String())
		}
		var enrolled struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &enrolled); err != nil || enrolled.Token == "" {
			t.Fatalf("decode enrol response: %v", err)
		}

		rec = fleetCall(fleetHandler, http.MethodGet, "/api/v1/fleet/privacy-policy", enrolled.Token, nil, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("agent policy status = %d (%s), want 200", rec.Code, rec.Body.String())
		}
		var envelope privacyPolicyAssignmentEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode agent assignment: %v", err)
		}
		if envelope.Assignment.Policy.HashSalt != salt {
			t.Fatalf("agent hash salt = %q, want %q — source-side hashing needs it", envelope.Assignment.Policy.HashSalt, salt)
		}
	})
}
