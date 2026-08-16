package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
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

// TestEveryAgentRouteReachesTheAgentPlane keeps the mount list honest for routes that do not exist
// yet. It iterates fleetAgentPlaneRoutes - the SAME declaration fleetRouter.handler() registers -
// rather than a hand-copied path list, and drives each route through the real Handler(). A new agent
// route therefore fails this test automatically: without a matching mount it falls through to the
// human chain and answers 401 instead of reaching the agent plane.
//
// The 400 expectation is the agent plane's own protocol-version check, which every agent route runs
// before auth. Reaching it proves the request was served by the agent mux, not the human chain.
func TestEveryAgentRouteReachesTheAgentPlane(t *testing.T) {
	handler := routerWithFleetPlanes(t)
	for _, route := range fleetAgentPlaneRoutes() {
		method, pattern, ok := strings.Cut(route.pattern, " ")
		if !ok {
			t.Fatalf("route %q has no method", route.pattern)
		}
		// Substitute a concrete value for each wildcard so the request matches the pattern.
		path := wildcardRE.ReplaceAllString(pattern, "wo1")
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(method, path, http.NoBody)
			// Deliberately no X-Synapse-Fleet-Proto header and no credential.
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code == http.StatusUnauthorized {
				t.Fatalf("%s was served by the HUMAN chain (401); it needs a mount in fleetAgentPlaneRoutes", path)
			}
			if recorder.Code == http.StatusNotFound {
				t.Fatalf("%s answered 404; the agent plane is mounted but does not serve it", path)
			}
			if recorder.Code != http.StatusBadRequest {
				t.Errorf("%s status = %d, want 400 from the agent-plane protocol-version check", path, recorder.Code)
			}
		})
	}
}

// wildcardRE matches a net/http mux wildcard segment such as "{id}".
var wildcardRE = regexp.MustCompile(`\{[^}]*\}`)

// TestFleetAgentPlaneRoutesAllHaveHandlers guards the other direction: handler() skips a declared
// pattern it has no handler for, which would otherwise be a silent 404 on a mounted agent path.
func TestFleetAgentPlaneRoutesAllHaveHandlers(t *testing.T) {
	agentSvc, err := fleetagentuc.NewService(memory.NewFleetAgentStore(), ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("agent svc: %v", err)
	}
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, nil, time.Now, "")
	mux, ok := rt.fleet.handler().(*http.ServeMux)
	if !ok {
		t.Fatal("agent plane handler is not a *http.ServeMux")
	}
	for _, route := range fleetAgentPlaneRoutes() {
		method, pattern, _ := strings.Cut(route.pattern, " ")
		path := wildcardRE.ReplaceAllString(pattern, "wo1")
		if _, matched := mux.Handler(httptest.NewRequest(method, path, http.NoBody)); matched == "" {
			t.Errorf("declared route %q registered no handler; it would 404 on a mounted path", route.pattern)
		}
	}
}
