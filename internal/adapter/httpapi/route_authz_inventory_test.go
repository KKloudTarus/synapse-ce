package httpapi

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every route on the human plane must pass the authorization chokepoint. The one class of defect
// this catches is the one that shipped: a route registered directly against the mux, with no
// authz wrapper, because the handler "obviously" only returns the caller's own data. An inventory
// test is the cheap guard, since the hostile harness can only cover routes someone remembered to
// add to its table.
//
// publicRoutePatterns are the deliberate exceptions: liveness and readiness probes, the identity
// and consent routes a brand-new principal must reach before it has any role, and the OIDC login
// callback. Adding to this list is a security decision, so it lives here in one visible place.
var publicRoutePatterns = map[string]string{
	"GET /healthz":                "liveness probe, documented as unauthenticated",
	"GET /readyz":                 "readiness probe, documented as unauthenticated",
	"GET /api/v1/aup":             "a new principal must read the policy before it can accept it",
	"POST /api/v1/aup/accept":     "the consent gate itself; the caller is authenticated but has no role yet",
	"GET /api/v1/me":              "identity echo for the authenticated caller, no tenant data",
	"GET /api/auth/oidc/login":    "starts the login redirect, before any principal exists",
	"GET /api/auth/oidc/callback": "completes the login redirect, before any principal exists",
	"GET /api/auth/session":       "session probe the dashboard calls on every page",
	"POST /api/auth/logout":       "ends the caller's own session; must work for any role",
}

var routeRegistration = regexp.MustCompile(`mux\.HandleFunc\("((?:GET|POST|PUT|PATCH|DELETE|HEAD) [^"]+)",\s*([^\n]*)`)

// TestEveryHumanRouteGoesThroughAuthz walks the route table in router.go and fails for any route
// registered without rt.authz, unless it is listed above as a deliberate exception.
func TestEveryHumanRouteGoesThroughAuthz(t *testing.T) {
	source := routerSource(t)
	matches := routeRegistration.FindAllStringSubmatch(source, -1)
	if len(matches) < 100 {
		t.Fatalf("found %d route registrations; the inventory is no longer reading the route table", len(matches))
	}

	var unguarded []string
	for _, m := range matches {
		pattern, registration := m[1], m[2]
		if _, public := publicRoutePatterns[pattern]; public {
			continue
		}
		if strings.Contains(registration, "rt.authz(") {
			continue
		}
		unguarded = append(unguarded, pattern)
	}
	sort.Strings(unguarded)
	for _, pattern := range unguarded {
		t.Errorf("route %q is registered without rt.authz and is not a documented public route", pattern)
	}
}

// TestPublicRouteExceptionsAreAllRegistered keeps the exception list honest: an entry that no
// longer matches a real route is a stale exemption that would hide the next unguarded route.
func TestPublicRouteExceptionsAreAllRegistered(t *testing.T) {
	source := routerSource(t)
	registered := map[string]bool{}
	for _, m := range routeRegistration.FindAllStringSubmatch(source, -1) {
		registered[m[1]] = true
	}
	for pattern := range publicRoutePatterns {
		if !registered[pattern] {
			t.Errorf("public-route exception %q matches no registered route; remove the stale exemption", pattern)
		}
	}
}

// TestTenantScopedRoutesAreCoveredByTheHostileHarness reports how much of the tenant-scoped
// surface the cross-tenant harness actually probes. The harness table is hand-maintained, so a
// route added today is silently uncovered tomorrow; this makes the gap visible and stops it from
// growing.
func TestTenantScopedRoutesAreCoveredByTheHostileHarness(t *testing.T) {
	source := routerSource(t)
	harness := harnessSource(t)

	tenantScoped := map[string]bool{}
	for _, m := range routeRegistration.FindAllStringSubmatch(source, -1) {
		pattern := m[1]
		// Routes under an engagement, a project or an asset carry another tenant's data when the
		// path id is guessed, which is exactly what the harness exists to reject.
		if strings.Contains(pattern, "/engagements/{") || strings.Contains(pattern, "/projects/{") || strings.Contains(pattern, "/assets/{") {
			tenantScoped[pattern] = true
		}
	}
	if len(tenantScoped) == 0 {
		t.Fatal("found no tenant-scoped routes; the inventory is no longer reading the route table")
	}

	covered := 0
	var uncovered []string
	for pattern := range tenantScoped {
		path := pattern[strings.Index(pattern, " ")+1:]
		// The harness writes concrete paths, so compare on the fixed prefix before the first
		// path parameter plus the segment that follows it.
		prefix := path
		if i := strings.Index(path, "/{"); i >= 0 {
			prefix = path[:i]
		}
		if strings.Contains(harness, prefix) {
			covered++
			continue
		}
		uncovered = append(uncovered, pattern)
	}
	sort.Strings(uncovered)

	// The harness covered 115 of the tenant-scoped route prefixes when this guard was written.
	// The ratchet may only improve: raise the floor when you add coverage, never lower it.
	const minimumCovered = 115
	if covered < minimumCovered {
		t.Errorf("hostile harness covers %d tenant-scoped routes, below the ratchet of %d; add cases rather than lowering the floor.\nUncovered:\n  %s",
			covered, minimumCovered, strings.Join(uncovered, "\n  "))
	}
	t.Logf("hostile harness covers %d of %d tenant-scoped routes; %d uncovered", covered, len(tenantScoped), len(uncovered))
}
