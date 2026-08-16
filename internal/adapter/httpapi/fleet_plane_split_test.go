package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
)

// routerWithFleetPlanes builds a Router that has BOTH planes wired, then returns the real
// Handler() - the composition the server actually serves. The other fleet tests drive
// rt.routes() or rt.fleet.handler() in isolation, so neither of them can observe how the two
// planes are mounted relative to each other.
func routerWithFleetPlanes(t *testing.T) http.Handler {
	t.Helper()
	agentSvc, err := fleetagentuc.NewService(memory.NewFleetAgentStore(), ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("agent svc: %v", err)
	}
	signer, err := worksign.New([]byte("0123456789012345678901234567890123"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	workSvc, err := fleetwork.NewService(memory.NewWorkOrderStore(), signer, ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("work svc: %v", err)
	}
	auth := NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
		if token == "operator-secret" {
			return Principal{ID: "u1", Name: "Operator", Role: "admin", TenantID: "tenantA"}, true
		}
		return Principal{}, false
	})
	rt := &Router{log: discardLog(), auth: auth}
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
	rt.SetFleetAdmin(agentSvc)
	rt.SetFleetCoverage(fakeCoverage{})
	return rt.Handler()
}

// TestFleetOperatorRoutesAreNotShadowedByAgentPlane pins the boundary between the two auth planes.
// Mounting the untrusted agent plane on the whole "/api/v1/fleet/" prefix also swallowed the
// OPERATOR coverage + agent-health routes, which the agent mux does not serve: every one of them
// answered Go's default 404 instead of reaching the human RBAC chain, so the Fleet coverage UI was
// dead on a real server. Unauthenticated is the discriminator - a human-plane route rejects with
// 401 (the authenticator runs first), while a shadowed route 404s before any auth runs.
func TestFleetOperatorRoutesAreNotShadowedByAgentPlane(t *testing.T) {
	h := routerWithFleetPlanes(t)
	for _, path := range []string{
		"/api/v1/fleet/agents",
		"/api/v1/fleet/agents/ag1",
		"/api/v1/fleet/coverage",
		"/api/v1/fleet/coverage/summary",
		"/api/v1/fleet/coverage/export",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code == http.StatusNotFound {
				t.Fatalf("%s answered 404: the agent plane is shadowing an operator route", path)
			}
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s status = %d, want 401 (human RBAC plane must authenticate it)", path, w.Code)
			}
		})
	}
}

// TestFleetAgentPlaneStaysOffTheHumanChain is the other half of the split: the agent transport must
// NOT gain the human bearer authenticator or the AUP gate. An agent route reaching the human chain
// would answer 401 for a missing operator token; on its own plane it answers the protocol-version
// check instead, proving it never saw human auth.
func TestFleetAgentPlaneStaysOffTheHumanChain(t *testing.T) {
	h := routerWithFleetPlanes(t)
	for _, path := range []string{
		"/api/v1/fleet/enrol",
		"/api/v1/fleet/heartbeat",
		"/api/v1/fleet/decommission",
		"/api/v1/fleet/work/claim",
		"/api/v1/fleet/work/wo1/progress",
		"/api/v1/fleet/work/wo1/result",
		"/api/v1/fleet/inventory/cluster",
		"/api/v1/fleet/inventory/host",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			// No X-Synapse-Fleet-Proto header: the agent plane rejects with 400 unsupported_version.
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
			if w.Code == http.StatusUnauthorized {
				t.Fatalf("%s answered 401: the agent route was routed through the human auth chain", path)
			}
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s status = %d, want 400 from the agent-plane version check", path, w.Code)
			}
		})
	}
}

// TestFleetAgentPlanePrefixesCoverEveryAgentRoute keeps the mount list honest: a new agent-plane
// route that no prefix covers would silently fall through to the human chain and be rejected as an
// unauthenticated operator request.
func TestFleetAgentPlanePrefixesCoverEveryAgentRoute(t *testing.T) {
	for _, path := range []string{
		"/api/v1/fleet/enrol",
		"/api/v1/fleet/heartbeat",
		"/api/v1/fleet/decommission",
		"/api/v1/fleet/work/claim",
		"/api/v1/fleet/work/wo1/progress",
		"/api/v1/fleet/work/wo1/result",
		"/api/v1/fleet/inventory/cluster",
		"/api/v1/fleet/inventory/host",
	} {
		covered := false
		for _, prefix := range fleetAgentPlanePrefixes {
			if path == prefix || (len(prefix) > 0 && prefix[len(prefix)-1] == '/' && len(path) >= len(prefix) && path[:len(prefix)] == prefix) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("agent route %s is not covered by fleetAgentPlanePrefixes", path)
		}
	}
}
