package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
)

// The human guard tests read the human mux. Three other muxes serve requests that never reach it: the
// outer mux Router.Handler puts in front of the human chain, the agent-plane mux and the egress grant
// listener. None of their routes passes through the human authentication, the AUP gate or a per-route
// guard, and until #1702 none of them was read by any inventory test either, so a route added there
// without a guard turned nothing red. This file reads every one of them.

// outerMuxFunc is the function that builds the outer mux. A registration anywhere else in router.go is
// on the human mux and is held to the human guards.
const outerMuxFunc = "Router.Handler"

// funcLiteralHandler stands for a handler written inline as a function literal. The entry's reason
// then says what the literal checks before it reads anything.
const funcLiteralHandler = "func literal"

// nonHumanRoute is the one handler a registration outside the human mux may be served by, and why that
// handler authenticates its caller itself.
type nonHumanRoute struct {
	handler string // the handler argument as the parser prints it
	reason  string
}

// nonHumanRoutes lists every registration outside the human mux, by the function that makes it. A
// registration that ranges over a route table is listed once, as "table()", and its rows are checked
// by the table's own test. Adding an entry is a security decision, exactly like publicRoutePatterns.
var nonHumanRoutes = map[string]map[string]nonHumanRoute{
	outerMuxFunc: {
		"POST /api/v1/hooks/{public_id}": {"rt.inboundWebhooks.handle",
			"inbound webhook: the body's HMAC signature is checked against the secret of the endpoint the public id names, and a human credential is never accepted (TestWebhookAndHumanCredentialPlanesAreSeparate)"},
		"POST /api/v1/teams/messages": {"rt.handleTeamsActivity",
			"Teams bot endpoint (#1420): the Bot Framework JWT is verified with the activity's serviceUrl bound before the activity is acted on (TestTeamsBotEndpointNeedsTheBotFrameworkToken)"},
		"/": {"human",
			"the human chain: authentication, the AUP gate and the per-route guards that TestEveryHumanRouteGoesThroughAuthz reads"},
		"fleetAgentPlaneMounts()": {"agentPlane",
			"the agent plane: its mux serves only the rows of fleetAgentPlaneRoutes, each behind the guard it declares (TestEveryAgentPlaneRouteDeclaresAGuard)"},
	},
	"fleetRouter.handler": {
		"fleetAgentPlaneRoutes()": {"f.guard(route.guard, route.handler(f))",
			"every row is served behind the guard it declares: per-IP throttle and protocol check, then the mTLS header or agent bearer with a per-agent throttle, or the enrolment host and one-use token"},
	},
	"newEgressGrantHandler": {
		"POST /internal/v1/egress-grants": {funcLiteralHandler,
			"machine route on a private listener: the bearer token is compared in constant time before the body is read, then a per-minute limit applies (TestEgressGrantHandlerFailsClosed)"},
	},
}

// agentPlaneEnrolmentRoutes are the agent-plane rows that run before the agent holds a credential, so
// they cannot demand one. Each is a security decision with its reason.
var agentPlaneEnrolmentRoutes = map[string]string{
	"POST /api/v1/fleet/enrol": "redeems a one-use enrolment token on the enrolment host and issues the agent credential",
}

// routePatternSources supplies the patterns a file builds from a declaration instead of writing them as
// literals, read from that same declaration at run time so the inventory sees what the router serves.
func routePatternSources(file string) []PatternSource {
	switch file {
	case "router.go":
		return []PatternSource{{Range: "fleetAgentPlaneMounts", Expr: "mount", Patterns: fleetAgentPlaneMounts()}}
	case "fleet_handler.go":
		var patterns []string
		for _, route := range fleetAgentPlaneRoutes() {
			patterns = append(patterns, route.pattern)
		}
		return []PatternSource{{Range: "fleetAgentPlaneRoutes", Expr: "route.pattern", Patterns: patterns}}
	case "egress_grant_handler.go":
		return []PatternSource{{Expr: `"POST " + EgressGrantPath`, Patterns: []string{"POST " + EgressGrantPath}}}
	}
	return nil
}

// routerRegistrations reads router.go and splits it into the human mux and the outer mux.
func routerRegistrations(t *testing.T) (human, outer []RouteRegistration) {
	t.Helper()
	routes, err := ParseRouteRegistrations("router.go", routePatternSources("router.go")...)
	if err != nil {
		t.Fatalf("read the route table: %v", err)
	}
	for _, route := range routes {
		if route.Func == outerMuxFunc {
			outer = append(outer, route)
		} else {
			human = append(human, route)
		}
	}
	return human, outer
}

// nonHumanRegistrations reads every registration outside the human mux.
func nonHumanRegistrations(t *testing.T) []RouteRegistration {
	t.Helper()
	_, routes := routerRegistrations(t)
	for _, file := range nonHumanRouteFiles {
		parsed, err := ParseRouteRegistrations(file, routePatternSources(file)...)
		if err != nil {
			t.Fatal(err)
		}
		routes = append(routes, parsed...)
	}
	return routes
}

// TestEveryNonHumanRouteHasAReasonedEntry fails for a registration outside the human mux that
// nonHumanRoutes does not list, for one served by a handler other than the listed one, and for an
// entry nothing registers any more, which would be a stale exemption waiting to cover the next route.
func TestEveryNonHumanRouteHasAReasonedEntry(t *testing.T) {
	seen := map[string]map[string]bool{}
	counts := map[string]int{}
	checked := map[string]bool{}
	for _, route := range nonHumanRegistrations(t) {
		key := route.Pattern
		if route.Table != "" {
			key = route.Table + "()"
		}
		counts[route.Func]++
		// The rows of one table registration share its line, so check each registration once.
		registration := fmt.Sprintf("%s %s %d", route.Func, key, route.Line)
		if checked[registration] {
			continue
		}
		checked[registration] = true
		entry, ok := nonHumanRoutes[route.Func][key]
		if !ok {
			t.Errorf("%s registers %s on %s (line %d) outside the human mux, where no human guard applies, and nonHumanRoutes has no entry for it",
				route.Func, key, route.Mux, route.Line)
			continue
		}
		if seen[route.Func] == nil {
			seen[route.Func] = map[string]bool{}
		}
		seen[route.Func][key] = true
		handlerMatches := route.Handler == entry.handler ||
			(entry.handler == funcLiteralHandler && strings.HasPrefix(route.Handler, "func("))
		if !handlerMatches {
			t.Errorf("%s registers %s with handler %q, but its entry is for %q; the reason no longer describes what serves it",
				route.Func, key, route.Handler, entry.handler)
		}
		if strings.TrimSpace(entry.reason) == "" {
			t.Errorf("%s %s has an entry with no reason", route.Func, key)
		}
	}
	var stale []string
	for fn, entries := range nonHumanRoutes {
		for key := range entries {
			if !seen[fn][key] {
				stale = append(stale, fn+" "+key)
			}
		}
	}
	sort.Strings(stale)
	for _, entry := range stale {
		t.Errorf("nonHumanRoutes entry %s matches no registration; remove the stale exemption", entry)
	}
	t.Logf("registrations outside the human mux, by function: %v", counts)
}

// TestEveryAgentPlaneRouteDeclaresAGuard reads the agent-plane table the registration loop serves. A
// row that declares no guard is refused at run time, and fails here first; a row that takes no agent
// credential must be a listed enrolment route.
func TestEveryAgentPlaneRouteDeclaresAGuard(t *testing.T) {
	enrolment := map[string]bool{}
	counts := map[string]int{}
	for _, route := range fleetAgentPlaneRoutes() {
		switch route.guard {
		case fleetGuardAgent:
			counts["agent credential"]++
			if _, listed := agentPlaneEnrolmentRoutes[route.pattern]; listed {
				t.Errorf("agent-plane route %s is listed as an enrolment route but declares the agent guard", route.pattern)
			}
		case fleetGuardEnrolment:
			counts["enrolment"]++
			enrolment[route.pattern] = true
			if _, listed := agentPlaneEnrolmentRoutes[route.pattern]; !listed {
				t.Errorf("agent-plane route %s declares the enrolment guard, which takes no agent credential, and is not in agentPlaneEnrolmentRoutes", route.pattern)
			}
		default:
			t.Errorf("agent-plane route %s declares no guard (%d)", route.pattern, route.guard)
		}
	}
	for pattern := range agentPlaneEnrolmentRoutes {
		if !enrolment[pattern] {
			t.Errorf("agentPlaneEnrolmentRoutes lists %s, which is not an enrolment row of fleetAgentPlaneRoutes", pattern)
		}
	}
	t.Logf("agent-plane routes by declared guard: %v", counts)
}

// TestAgentPlaneGuardsAreAppliedAsDeclared drives each declared guard as the registration loop applies
// it. The undeclared zero value must refuse even a request that passes every other check.
func TestAgentPlaneGuardsAreAppliedAsDeclared(t *testing.T) {
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
	rt := &Router{log: discardLog(), auth: NewAuthenticator(func(context.Context, string) (Principal, error) { return Principal{}, errTestCredentialInvalid })}
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")

	for name, tc := range map[string]struct {
		guard   fleetRouteGuard
		proto   bool
		want    int
		reached bool
	}{
		"undeclared":                   {fleetGuardUndeclared, true, http.StatusInternalServerError, false},
		"agent, no protocol header":    {fleetGuardAgent, false, http.StatusBadRequest, false},
		"agent, no credential":         {fleetGuardAgent, true, http.StatusUnauthorized, false},
		"enrolment, no protocol":       {fleetGuardEnrolment, false, http.StatusBadRequest, false},
		"enrolment, protocol accepted": {fleetGuardEnrolment, true, http.StatusNoContent, true},
	} {
		t.Run(name, func(t *testing.T) {
			reached := false
			handler := rt.fleet.guard(tc.guard, func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/probe", http.NoBody)
			if tc.proto {
				req.Header.Set("X-Synapse-Fleet-Proto", FleetProtoVersion)
			}
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != tc.want || reached != tc.reached {
				t.Errorf("status %d, handler reached %v; want %d, reached %v", rec.Code, reached, tc.want, tc.reached)
			}
		})
	}
}
