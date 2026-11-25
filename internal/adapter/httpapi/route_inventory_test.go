package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copyFixture writes a .go.txt fixture out as a .go file the parser can read. The fixtures are kept
// with a .txt suffix so the package still builds; they are deliberately not valid programs.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), strings.TrimSuffix(name, ".txt"))
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestParseRouteRegistrationsSeesEveryRegistrationForm proves the inventory cannot be walked past.
// Each case here is an escape that a text search over the route table would have missed.
func TestParseRouteRegistrationsSeesEveryRegistrationForm(t *testing.T) {
	routes, err := ParseRouteRegistrations(copyFixture(t, "router_forms.go.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got := map[string]string{}
	for _, route := range routes {
		got[route.Pattern] = route.Guard
	}
	want := map[string]string{
		"GET /guarded":    "rt.authz",
		"GET /public":     "",
		"GET /commented":  "",
		"GET /multiline":  "",
		"GET /via-handle": "",
		"GET /nested":     "rt.authz",
		"GET /platform":   "rt.authz",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d routes, want %d: %v", len(got), len(want), got)
	}
	for pattern, wantGuard := range want {
		guard, ok := got[pattern]
		if !ok {
			t.Errorf("route %q was not seen at all", pattern)
			continue
		}
		if guard != wantGuard {
			t.Errorf("route %q guard = %q, want %q", pattern, guard, wantGuard)
		}
	}
}

// TestParseRouteRegistrationsRefusesAPatternItCannotRead is the property that makes the inventory
// trustworthy: a registration it cannot model is an error, never a silent omission that reads as a
// route with no problems.
func TestParseRouteRegistrationsRefusesAPatternItCannotRead(t *testing.T) {
	_, err := ParseRouteRegistrations(copyFixture(t, "router_variable_pattern.go.txt"))
	if err == nil {
		t.Fatal("a non-literal route pattern was accepted; the inventory would skip it silently")
	}
	if !strings.Contains(err.Error(), "not a string literal") {
		t.Errorf("error = %v, want it to name the unreadable pattern", err)
	}
}

// TestParseRouteRegistrationsReadsEveryServeMux proves the receiver's name does not decide whether a
// registration is read. Router.Handler registers on a mux called top, and those routes once passed
// every guard test unread because the parser only looked at receivers named mux (#1702).
func TestParseRouteRegistrationsReadsEveryServeMux(t *testing.T) {
	routes, err := ParseRouteRegistrations(copyFixture(t, "router_receivers.go.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	type seen struct{ mux, fn, guard string }
	got := map[string]seen{}
	for _, route := range routes {
		got[route.Pattern] = seen{route.Mux, route.Func, route.Guard}
	}
	want := map[string]seen{
		"GET /param":      {"m", "Router.register", "rt.authz"},
		"POST /local":     {"top", "Router.Handler", ""},
		"GET /value":      {"value", "Router.Handler", ""},
		"GET /new":        {"allocated", "Router.Handler", ""},
		"GET /literal":    {"literal", "Router.Handler", ""},
		"GET /alias":      {"alias", "Router.Handler", ""},
		"GET /file-level": {"shared", "Router.Handler", ""},
		"GET /default":    {"http.DefaultServeMux", "Router.Handler", ""},
		"GET /closure":    {"inner", "Router.Handler", ""},
	}
	if len(got) != len(want) {
		t.Errorf("parsed %d routes, want %d: %v", len(got), len(want), got)
	}
	for pattern, w := range want {
		g, ok := got[pattern]
		if !ok {
			t.Errorf("route %q was not seen at all", pattern)
			continue
		}
		if g != w {
			t.Errorf("route %q = %+v, want %+v", pattern, g, w)
		}
	}
}

// TestParseRouteRegistrationsRefusesAReceiverItCannotType keeps the widened parser fail-closed: a
// Handle or HandleFunc call whose receiver is not declared in the file as a ServeMux is an error,
// and so is the registration method taken as a value, which would otherwise register out of sight.
func TestParseRouteRegistrationsRefusesAReceiverItCannotType(t *testing.T) {
	_, err := ParseRouteRegistrations(copyFixture(t, "router_untyped_receiver.go.txt"))
	if err == nil {
		t.Fatal("registrations on receivers the parser cannot type were accepted")
	}
	for _, want := range []string{"rt.side", "receiver built", "receiver undeclared", "mux.HandleFunc is used as a value"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

// TestParseRouteRegistrationsReadsPatternsFromTheirDeclaration covers registrations whose pattern is
// built rather than written: a loop over a declared route table, and a constant expression. The
// parser cannot evaluate either, so it refuses them until the caller supplies the values it read from
// the same declaration at run time, and it refuses a supplied source that matches nothing.
func TestParseRouteRegistrationsReadsPatternsFromTheirDeclaration(t *testing.T) {
	path := copyFixture(t, "router_pattern_sources.go.txt")
	table := PatternSource{Range: "agentRoutes", Expr: "route.pattern", Patterns: []string{"POST /a", "GET /b"}}
	constant := PatternSource{Expr: `"POST " + basePath`, Patterns: []string{"POST /internal/v1/things"}}

	_, err := ParseRouteRegistrations(path)
	if err == nil {
		t.Fatal("patterns built from a table and a constant were accepted with no source")
	}
	for _, want := range []string{"route.pattern is not a string literal", "agentRoutes()", `"POST " + basePath is not a string literal`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}

	routes, err := ParseRouteRegistrations(path, table, constant)
	if err != nil {
		t.Fatalf("parse with sources: %v", err)
	}
	var got []string
	for _, route := range routes {
		got = append(got, route.Pattern+" table="+route.Table+" guard="+route.Guard+" handler="+route.Handler)
	}
	want := []string{
		"POST /a table=agentRoutes guard=f.guard handler=f.guard(route.guard, route.handler(f))",
		"GET /b table=agentRoutes guard=f.guard handler=f.guard(route.guard, route.handler(f))",
		"POST /internal/v1/things table= guard= handler=f.thing",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("routes =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}

	for name, sources := range map[string][]PatternSource{
		"a source no registration uses":  {table, constant, {Range: "otherRoutes", Expr: "route.pattern", Patterns: []string{"GET /c"}}},
		"a table named for another loop": {{Range: "otherRoutes", Expr: "route.pattern", Patterns: []string{"GET /c"}}, constant},
		"a source with no patterns":      {{Range: "agentRoutes", Expr: "route.pattern"}, constant},
	} {
		if _, err := ParseRouteRegistrations(path, sources...); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
