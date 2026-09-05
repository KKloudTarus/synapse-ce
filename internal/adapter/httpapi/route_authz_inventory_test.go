package httpapi

import (
	"fmt"
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

// registeredRoutes parses router.go into the routes it actually registers. Parsing rather than
// matching text is what makes the guards below hard to fool: a registration written across several
// lines, one built with mux.Handle, or a line that merely mentions rt.authz in a comment all read
// correctly, and a form the parser does not model is a failure rather than a silent skip.
func registeredRoutes(t *testing.T) []RouteRegistration {
	t.Helper()
	routes, err := ParseRouteRegistrations("router.go")
	if err != nil {
		t.Fatalf("read the route table: %v", err)
	}
	if len(routes) < 100 {
		t.Fatalf("found %d route registrations; the inventory is no longer reading the route table", len(routes))
	}
	return routes
}

// TestEveryHumanRouteGoesThroughAuthz walks the route table in router.go and fails for any route
// registered without rt.authz, unless it is listed above as a deliberate exception.
func TestEveryHumanRouteGoesThroughAuthz(t *testing.T) {
	var unguarded []string
	for _, route := range registeredRoutes(t) {
		if _, public := publicRoutePatterns[route.Pattern]; public {
			continue
		}
		if route.Guard == "rt.authz" {
			continue
		}
		unguarded = append(unguarded, fmt.Sprintf("%s (router.go:%d, outermost wrapper %q)", route.Pattern, route.Line, route.Guard))
	}
	sort.Strings(unguarded)
	for _, route := range unguarded {
		t.Errorf("route %s is registered without rt.authz and is not a documented public route", route)
	}
}

// TestPublicRouteExceptionsAreAllRegistered keeps the exception list honest in both directions: an
// entry that matches no real route is a stale exemption that would hide the next unguarded route,
// and an entry for a route that IS wrapped in rt.authz is an exemption nobody needs.
func TestPublicRouteExceptionsAreAllRegistered(t *testing.T) {
	registered := map[string]RouteRegistration{}
	for _, route := range registeredRoutes(t) {
		registered[route.Pattern] = route
	}
	for pattern := range publicRoutePatterns {
		route, ok := registered[pattern]
		if !ok {
			t.Errorf("public-route exception %q matches no registered route; remove the stale exemption", pattern)
			continue
		}
		if route.Guard == "rt.authz" {
			t.Errorf("public-route exception %q is in fact wrapped in rt.authz; remove the exemption rather than leaving it to cover a future route", pattern)
		}
	}
}

// TestTenantScopedRoutesAreCoveredByTheHostileHarness reports how much of the tenant-scoped
// surface the cross-tenant harness actually probes, so the gap is visible and cannot grow.
//
// Coverage is measured on the WHOLE pattern with its parameters filled in, not on the fixed prefix
// before the first parameter. Measuring the prefix counts every route under /api/v1/engagements as
// covered the moment the harness mentions any engagement path once, so the number rises with each
// new route and the guard can never fire for the case it exists to catch.
func TestTenantScopedRoutesAreCoveredByTheHostileHarness(t *testing.T) {
	harness := harnessSource(t)

	tenantScoped := map[string]bool{}
	for _, route := range registeredRoutes(t) {
		pattern := route.Pattern
		// Routes under an engagement, a project or an asset carry another tenant's data when the
		// path id is guessed, which is exactly what the harness exists to reject.
		if strings.Contains(pattern, "/engagements/{") || strings.Contains(pattern, "/projects/{") || strings.Contains(pattern, "/assets/{") {
			tenantScoped[pattern] = true
		}
	}
	if len(tenantScoped) == 0 {
		t.Fatal("found no tenant-scoped routes; the inventory is no longer reading the route table")
	}

	// Every (method, path) pair the harness actually sends, including the generated sweep, which
	// builds its paths from this same route table.
	type request struct{ method, path string }
	var sent []request
	for _, m := range harnessRequest.FindAllStringSubmatch(harness, -1) {
		sent = append(sent, request{method: strings.ToUpper(m[1]), path: m[2]})
	}
	for _, route := range tenantScopedGETRoutes(t) {
		if path := concreteHarnessPath(route); path != "" {
			sent = append(sent, request{method: "GET", path: path})
		}
	}
	if len(sent) < 40 {
		t.Fatalf("read %d harness requests; the harness is no longer being parsed", len(sent))
	}

	covered := 0
	var uncovered []string
	for pattern := range tenantScoped {
		method, path, _ := strings.Cut(pattern, " ")
		matcher := patternMatcher(path)
		hit := false
		for _, req := range sent {
			if req.method == method && matcher.MatchString(req.path) {
				hit = true
				break
			}
		}
		if hit {
			covered++
			continue
		}
		uncovered = append(uncovered, pattern)
	}
	sort.Strings(uncovered)

	// The honest measurement when this guard was rewritten. The ratchet may only improve: raise the
	// floor when you add coverage, never lower it.
	const minimumCovered = 94
	if covered < minimumCovered {
		t.Errorf("hostile harness covers %d of %d tenant-scoped routes, below the ratchet of %d; add cases rather than lowering the floor.\nUncovered:\n  %s",
			covered, len(tenantScoped), minimumCovered, strings.Join(uncovered, "\n  "))
	}
	t.Logf("hostile harness covers %d of %d tenant-scoped routes; %d uncovered", covered, len(tenantScoped), len(uncovered))
}

// harnessRequest matches the http.MethodX, "/path" pairs the harness sends, which is how a request
// appears both in its table entries and in its inline assertions.
var harnessRequest = regexp.MustCompile(`http\.Method(\w+),\s*"(/[^"]*)"`)

// patternMatcher turns a ServeMux pattern into a matcher for the concrete paths the harness sends.
// A {name} segment matches one path segment; a {name...} wildcard matches the rest of the path.
func patternMatcher(path string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for {
		open := strings.Index(path, "{")
		if open < 0 {
			b.WriteString(regexp.QuoteMeta(path))
			break
		}
		closeAt := strings.Index(path[open:], "}")
		if closeAt < 0 {
			b.WriteString(regexp.QuoteMeta(path))
			break
		}
		b.WriteString(regexp.QuoteMeta(path[:open]))
		if strings.HasSuffix(path[open:open+closeAt], "...") {
			b.WriteString(".+")
		} else {
			b.WriteString("[^/]+")
		}
		path = path[open+closeAt+1:]
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}
