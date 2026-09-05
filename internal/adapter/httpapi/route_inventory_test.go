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
