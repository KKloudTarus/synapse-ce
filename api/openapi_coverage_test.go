package api_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file guards OpenAPI COVERAGE, which the existing tests in this package deliberately do not.
//
// TestOpenAPI_StrictValidation, TestAttackPathOpenAPIContract, TestSLAOpenAPIContract, and
// TestSourcePublishOpenAPIContract all validate the spec against ITSELF: schema shape, $ref resolution,
// operationId uniqueness, example consistency, and a few hand-maintained path/method/operationId maps.
// None of them reads the router, so none can notice that a shipped endpoint is absent from the spec.
// That is how the API surface reached 215 registered operations against 74 described ones.
//
// The gap is recorded in testdata/openapi-coverage-debt.txt rather than tolerated silently. The tests
// below turn that file into a ratchet: a NEW undocumented route fails the build, and a route that gets
// documented must be removed from the debt list. The number can only go down.

const coverageDebtFile = "testdata/openapi-coverage-debt.txt"

// pathParam normalizes a path parameter name so renaming {id} to {engagementID} does not read as a new
// route. The spec and the router are compared on shape, not on parameter spelling.
var pathParam = regexp.MustCompile(`\{[a-zA-Z]+\}`)

// routeRegistrationFiles are the only non-test files that register routes. If a third file starts
// calling HandleFunc, TestRouteRegistrationFilesAreKnown fails so this list cannot silently go stale.
var routeRegistrationFiles = []string{
	"../internal/adapter/httpapi/router.go",
	"../internal/adapter/httpapi/fleet_handler.go",
}

// nonAPIRouteRegistrationFiles register routes on their own mux outside /api/v1, so this
// browser/human-facing spec does not describe them. Each is still held to registering NO /api/v1
// path by TestNonAPIRegistrationFilesStayOffTheAPISurface, so the exemption cannot become a way to
// ship an undocumented /api/v1 endpoint.
var nonAPIRouteRegistrationFiles = []string{
	// Machine-only egress grant authority on a separate private listener (/internal/v1).
	"../internal/adapter/httpapi/egress_grant_handler.go",
}

// TestOpenAPIRouteCoverage fails when a registered operation is neither described in openapi.yaml nor
// listed as known debt. This is the guard that prevents the coverage gap from growing.
func TestOpenAPIRouteCoverage(t *testing.T) {
	registered := registeredOperations(t)
	described := describedOperations(t)
	debt := coverageDebt(t)

	var undocumented []string
	for _, op := range registered {
		if described[op] || debt[op] {
			continue
		}
		undocumented = append(undocumented, op)
	}
	sort.Strings(undocumented)

	for _, op := range undocumented {
		t.Errorf("%s is registered but absent from api/openapi.yaml. Describe it in the spec. "+
			"Only add it to %s if it genuinely cannot be documented yet.", op, coverageDebtFile)
	}
}

// TestOpenAPIHasNoDeadOperations fails when the spec describes an operation the router does not register.
// This is the more dangerous direction: a generated client would call an endpoint that does not exist.
func TestOpenAPIHasNoDeadOperations(t *testing.T) {
	registered := map[string]bool{}
	for _, op := range registeredOperations(t) {
		registered[op] = true
	}

	described := make([]string, 0, len(describedOperations(t)))
	for op := range describedOperations(t) {
		described = append(described, op)
	}
	sort.Strings(described)

	for _, op := range described {
		// Health probes live outside /api/v1 and are registered separately; they are verified by the
		// public-endpoint assertions in openapi_test.go rather than here.
		if strings.HasSuffix(op, " /healthz") || strings.HasSuffix(op, " /readyz") {
			continue
		}
		if !registered[op] {
			t.Errorf("api/openapi.yaml describes %s but no route registers it; a generated client "+
				"would call a nonexistent endpoint", op)
		}
	}
}

// TestCoverageDebtHasNoStaleEntries fails when the debt list names an operation that is either no longer
// registered or has since been documented. Without this, the ratchet would slip: a documented endpoint
// could stay on the debt list and mask a later regression.
func TestCoverageDebtHasNoStaleEntries(t *testing.T) {
	registered := map[string]bool{}
	for _, op := range registeredOperations(t) {
		registered[op] = true
	}
	described := describedOperations(t)

	debt := make([]string, 0, len(coverageDebt(t)))
	for op := range coverageDebt(t) {
		debt = append(debt, op)
	}
	sort.Strings(debt)

	for _, op := range debt {
		switch {
		case described[op]:
			t.Errorf("%s is listed in %s but is now described in openapi.yaml; delete the line",
				op, coverageDebtFile)
		case !registered[op]:
			t.Errorf("%s is listed in %s but is no longer registered; delete the line",
				op, coverageDebtFile)
		}
	}
}

// TestRouteRegistrationFilesAreKnown fails when a non-test file outside routeRegistrationFiles calls
// HandleFunc. The coverage tests read only the known files, so an unlisted registration site would let
// undocumented routes escape the ratchet entirely.
func TestRouteRegistrationFilesAreKnown(t *testing.T) {
	known := map[string]bool{}
	for _, f := range append(routeRegistrationFiles, nonAPIRouteRegistrationFiles...) {
		known[filepath.ToSlash(filepath.Clean(f))] = true
	}

	entries, err := os.ReadDir("../internal/adapter/httpapi")
	if err != nil {
		t.Fatalf("read httpapi package: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.ToSlash(filepath.Join("../internal/adapter/httpapi", entry.Name()))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(data), "HandleFunc(") {
			continue
		}
		if !known[filepath.ToSlash(filepath.Clean(path))] {
			t.Errorf("%s registers routes but is not in routeRegistrationFiles; add it so its routes "+
				"are covered by the OpenAPI coverage guard", path)
		}
	}
}

// TestNonAPIRegistrationFilesStayOffTheAPISurface holds every exempted registration file to its
// reason for exemption: it must not register an /api/v1 path. Without this, adding a file to
// nonAPIRouteRegistrationFiles would silently exempt real API endpoints from the coverage ratchet.
func TestNonAPIRegistrationFilesStayOffTheAPISurface(t *testing.T) {
	for _, file := range nonAPIRouteRegistrationFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(string(data), "/api/v1") {
			t.Errorf("%s is exempted from OpenAPI coverage as a non-/api/v1 listener but mentions "+
				"/api/v1; describe its routes in the spec and move it to routeRegistrationFiles", file)
		}
	}
}

// registeredOperations returns the normalized "METHOD /path" operations registered in non-test code.
// It parses direct HandleFunc calls and the fleet agent plane's route descriptor literals. Supporting the
// descriptor table keeps the runtime's single source of truth auditable without requiring duplicated direct
// registrations. Other computed HandleFunc patterns fail instead of escaping coverage silently.
func registeredOperations(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	record := func(fset *token.FileSet, literal *ast.BasicLit) {
		pattern, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Errorf("unquote route pattern at %s: %v", fset.Position(literal.Pos()), err)
			return
		}
		method, path, ok := strings.Cut(pattern, " ")
		if !ok || !strings.HasPrefix(path, "/api/v1") {
			return
		}
		if method == "" || method != strings.ToUpper(method) {
			t.Errorf("invalid method-prefixed route %q at %s", pattern, fset.Position(literal.Pos()))
			return
		}
		op := method + " " + pathParam.ReplaceAllString(path, "{p}")
		if !seen[op] {
			seen[op] = true
			out = append(out, op)
		}
	}

	for _, file := range routeRegistrationFiles {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CompositeLit:
				literal, ok := fleetRoutePatternLiteral(value)
				if ok {
					record(fset, literal)
				}
			case *ast.CallExpr:
				if !isHandleFuncCall(value.Fun) || len(value.Args) == 0 {
					return true
				}
				literal, ok := value.Args[0].(*ast.BasicLit)
				if ok && literal.Kind == token.STRING {
					record(fset, literal)
					return true
				}
				if isFleetRoutePattern(value.Args[0]) {
					return true
				}
				t.Errorf("%s registers a route with an unsupported computed pattern at %s; use a direct string literal or the fleetAgentPlaneRoute descriptor so OpenAPI coverage is auditable", file, fset.Position(value.Args[0].Pos()))
			}
			return true
		})
	}
	if len(out) == 0 {
		t.Fatal("found no registered routes; the extraction is wrong")
	}
	sort.Strings(out)
	return out
}

// fleetRoutePatternLiteral recognizes an entry in fleetAgentPlaneRoutes. Its first two fields are the
// method-prefixed route pattern and the mounted /api/v1/fleet prefix.
func fleetRoutePatternLiteral(lit *ast.CompositeLit) (*ast.BasicLit, bool) {
	if len(lit.Elts) < 2 {
		return nil, false
	}
	pattern, ok := lit.Elts[0].(*ast.BasicLit)
	if !ok || pattern.Kind != token.STRING {
		return nil, false
	}
	mount, ok := lit.Elts[1].(*ast.BasicLit)
	if !ok || mount.Kind != token.STRING {
		return nil, false
	}
	patternValue, patternErr := strconv.Unquote(pattern.Value)
	mountValue, mountErr := strconv.Unquote(mount.Value)
	if patternErr != nil || mountErr != nil || !strings.Contains(patternValue, " /api/v1/fleet/") || !strings.HasPrefix(mountValue, "/api/v1/fleet/") {
		return nil, false
	}
	return pattern, true
}

func isFleetRoutePattern(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "pattern" {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == "route"
}

func isHandleFuncCall(fun ast.Expr) bool {
	switch expr := fun.(type) {
	case *ast.SelectorExpr:
		return expr.Sel.Name == "HandleFunc"
	case *ast.Ident:
		return expr.Name == "HandleFunc"
	default:
		return false
	}
}

// describedOperations returns the normalized operations declared in openapi.yaml. The spec is scanned
// line-wise for two-space-indented path keys and their four-space-indented HTTP verbs, which matches the
// document's existing layout and avoids taking a YAML dependency for a structural question.
func describedOperations(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}

	verbs := map[string]bool{
		"get": true, "post": true, "put": true, "patch": true,
		"delete": true, "head": true, "options": true,
	}

	out := map[string]bool{}
	inPaths := false
	currentPath := ""
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			inPaths = trimmed == "paths:"
			currentPath = ""
			continue
		}
		if !inPaths {
			continue
		}
		if strings.HasPrefix(line, "  /") && !strings.HasPrefix(line, "   ") {
			currentPath = pathParam.ReplaceAllString(strings.TrimSuffix(trimmed, ":"), "{p}")
			continue
		}
		if currentPath == "" || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		verb := strings.TrimSuffix(trimmed, ":")
		if verbs[strings.ToLower(verb)] {
			out[strings.ToUpper(verb)+" "+currentPath] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("found no operations in openapi.yaml; the extraction is wrong")
	}
	return out
}

// coverageDebt reads the accepted-gap list, ignoring comments and blank lines.
func coverageDebt(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(coverageDebtFile)
	if err != nil {
		t.Fatalf("read %s: %v", coverageDebtFile, err)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out[trimmed] = true
	}
	return out
}
