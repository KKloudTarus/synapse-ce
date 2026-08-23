// Package docs_test holds deterministic documentation-drift guards.
//
// The repository already proves the pattern in internal/domain/promotion/doc_drift_test.go: compare the
// code's own truth against the prose that documents it, and fail with a message naming both sides. These
// tests apply the same idea to the surfaces that drifted furthest — the configuration reference and the
// published navigation — so a future feature cannot ship an undocumented operator setting or an
// unreachable page without CI saying so.
package docs_test

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

// repoRoot resolves the repository root from this test's package directory (docs/).
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

// envRef matches a SYNAPSE_* environment-variable name in a Go string literal or in Markdown prose.
var envRef = regexp.MustCompile(`SYNAPSE_[A-Z0-9_]+`)

// envLiteral matches a quoted SYNAPSE_* literal, which is how production code names a variable it reads.
var envLiteral = regexp.MustCompile(`"(SYNAPSE_[A-Z0-9_]+)"`)

// classifiedEnv records every SYNAPSE_* variable that is deliberately absent from the operator-facing
// configuration reference, with the reason it is excluded. An entry here is a decision, not a backlog
// item: a variable that an operator can meaningfully set must be documented instead of listed.
//
// Keeping the reasons in code means a reviewer sees why something is excluded, and the stale-exclusion
// check below means an entry cannot outlive the code that justified it.
var classifiedEnv = map[string]string{
	// Test- and CI-only switches. They exist to make tests hermetic or to opt into slow suites, and
	// setting them in production would not change product behavior.
	"SYNAPSE_TEST_DB_DSN":     "test-only: Postgres DSN for integration tests",
	"SYNAPSE_TEST_DUR":        "test-only: bounded duration for time-sensitive tests",
	"SYNAPSE_LIVE_AI":         "test-only: opts into live-provider AI tests",
	"SYNAPSE_LIVE_LLM_TEST":   "test-only: opts into live LLM wire tests",
	"SYNAPSE_K8S_INTEGRATION": "test-only: opts into the kind-based Kubernetes suite",
	"SYNAPSE_EVAL_OUT":        "tooling-only: output path for the offline AI-triage evaluation harness",
	"SYNAPSE_EVAL_SBOM":       "tooling-only: SBOM input for the offline evaluation harness",
	"SYNAPSE_PROBE_SECRET":    "conformance-only: redaction marker injected into the sandbox probe by synapse-sandbox-check",

	// Internal IPC. The parent process creates these inherited file descriptors when it spawns a
	// sandboxed helper. An operator-supplied value would be meaningless or actively harmful, so they are
	// documented as parent-managed in the guide rather than presented as settings.
	"SYNAPSE_CSPM_CREDENTIAL_FD":    "internal IPC: inherited credential pipe for the CSPM helper",
	"SYNAPSE_CSPM_AUTH_REQUEST_FD":  "internal IPC: helper-to-parent authorization request pipe",
	"SYNAPSE_CSPM_AUTH_DECISION_FD": "internal IPC: parent-to-helper authorization decision pipe",
	"SYNAPSE_DAST_AUTH_REQUEST_FD":  "internal IPC: helper-to-parent authorization request pipe",
	"SYNAPSE_DAST_AUTH_DECISION_FD": "internal IPC: parent-to-helper authorization decision pipe",

	// A constructed prefix rather than a variable name. The code appends a vault placeholder name at
	// runtime, so there is no fixed key for an operator to set.
	"SYNAPSE_DAST_SECRET_": "prefix, not a variable: parent-projected vault placeholder for the DAST helper",
}

// TestConfigDocCoversEveryOperatorEnv fails when production code reads a SYNAPSE_* variable that the
// configuration reference neither documents nor explicitly classifies.
//
// This is the guard that would have caught the ~57 undocumented operator settings this audit found.
func TestConfigDocCoversEveryOperatorEnv(t *testing.T) {
	root := repoRoot(t)
	documented := documentedEnv(t, root)
	inCode := productionEnv(t, root)

	var undocumented []string
	for name := range inCode {
		if documented[name] {
			continue
		}
		if _, classified := classifiedEnv[name]; classified {
			continue
		}
		undocumented = append(undocumented, name)
	}
	sort.Strings(undocumented)

	for _, name := range undocumented {
		t.Errorf("%s is read by production code (%s) but is not in docs/guide/configuration.md; "+
			"document it, or add it to classifiedEnv with the reason it is not an operator setting",
			name, strings.Join(inCode[name], ", "))
	}
}

// TestConfigDocHasNoStaleVariables fails when the configuration reference documents a SYNAPSE_* variable
// that production code no longer reads. Stale documentation is worse than missing documentation: an
// operator will set a variable that does nothing and believe it took effect.
func TestConfigDocHasNoStaleVariables(t *testing.T) {
	root := repoRoot(t)
	documented := documentedEnv(t, root)
	inCode := productionEnv(t, root)

	var stale []string
	for name := range documented {
		if len(inCode[name]) == 0 {
			if _, classified := classifiedEnv[name]; classified {
				continue
			}
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)

	for _, name := range stale {
		t.Errorf("docs/guide/configuration.md documents %s but no production Go file reads it; "+
			"remove the row or wire the setting", name)
	}
}

// TestClassifiedEnvHasNoStaleEntries fails when classifiedEnv excuses a variable that no longer appears
// anywhere in the tree. Without this, an exclusion list silently becomes a list of fictional variables
// and stops being trustworthy.
func TestClassifiedEnvHasNoStaleEntries(t *testing.T) {
	root := repoRoot(t)
	all := allEnvMentions(t, root)

	var stale []string
	for name := range classifiedEnv {
		if !all[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)

	for _, name := range stale {
		t.Errorf("classifiedEnv excludes %s but it appears in no Go file; remove the exclusion", name)
	}
}

// TestSecuritySensitiveEnvDocumentsItsRisk pins the specific variables whose misconfiguration has a
// security consequence. Presence in the reference is not enough for these: the row must also carry the
// warning that explains why a careless value is dangerous.
func TestSecuritySensitiveEnvDocumentsItsRisk(t *testing.T) {
	reference := readFile(t, filepath.Join(repoRoot(t), "docs", "guide", "configuration.md"))

	cases := []struct {
		env  string
		want []string
		why  string
	}{
		{
			env:  "SYNAPSE_FLEET_CLIENT_CERT_HEADER",
			want: []string{"strip"},
			why:  "a proxy that forwards an unverified header turns this into an authentication bypass",
		},
		{
			env:  "SYNAPSE_FLEET_ENROL_TOKEN",
			want: []string{"file is preferred", "process listing"},
			why:  "a token passed as an argument leaks through ps and shell history",
		},
		{
			env:  "SYNAPSE_FLEET_CA_KEY",
			want: []string{"secret"},
			why:  "this key issues fleet client certificates",
		},
		{
			env:  "SYNAPSE_UPDATE_PUBLIC_KEY",
			want: []string{"override"},
			why:  "it replaces the key that verifies agent self-update artifacts",
		},
		{
			env:  "SYNAPSE_DB_MIGRATION_DSN",
			want: []string{"least-privileged"},
			why:  "its purpose is separating migration authority from runtime authority",
		},
	}

	for _, tc := range cases {
		row := documentedRow(reference, tc.env)
		if row == "" {
			t.Errorf("%s has no row in docs/guide/configuration.md (%s)", tc.env, tc.why)
			continue
		}
		lower := strings.ToLower(row)
		for _, phrase := range tc.want {
			if !strings.Contains(lower, strings.ToLower(phrase)) {
				t.Errorf("the %s row does not mention %q; %s", tc.env, phrase, tc.why)
			}
		}
	}
}

// documentedRow returns the configuration-reference line documenting env, preferring the row where the
// name appears in a table cell rather than an incidental cross-reference.
func documentedRow(reference, env string) string {
	for _, line := range strings.Split(reference, "\n") {
		if strings.Contains(line, "`"+env+"`") && strings.HasPrefix(strings.TrimSpace(line), "|") {
			return line
		}
	}
	return ""
}

// documentedEnv collects every SYNAPSE_* name mentioned in the configuration reference.
func documentedEnv(t *testing.T, root string) map[string]bool {
	t.Helper()
	reference := readFile(t, filepath.Join(root, "docs", "guide", "configuration.md"))
	out := map[string]bool{}
	for _, match := range envRef.FindAllString(reference, -1) {
		out[match] = true
	}
	return out
}

// productionEnv maps each SYNAPSE_* literal passed to an environment-reader call by non-test Go code
// to the files that read it. Scanning AST calls avoids treating diagnostic prose as an implemented setting.
// All current readers take the environment key as their first argument; non-literal keys fail closed.
func productionEnv(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, dir := range []string{"internal", "cmd"} {
		walkProductionGoFiles(t, filepath.Join(root, dir), func(path string) {
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			constants := stringConstants(parsed)
			rel, err := filepath.Rel(root, path)
			if err != nil {
				t.Fatalf("make %s relative to %s: %v", path, root, err)
			}
			rel = filepath.ToSlash(rel)
			ast.Inspect(parsed, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 || !isEnvReader(call.Fun) {
					return true
				}
				name, ok := environmentKey(call.Args[0], constants)
				if !ok {
					// Helpers such as getenv(key, def) legitimately forward a key. Their callers are
					// inspected independently, so there is no literal setting to classify at this call.
					return true
				}
				if !strings.HasPrefix(name, "SYNAPSE_") {
					return true
				}
				if !containsString(out[name], rel) {
					out[name] = append(out[name], rel)
				}
				return true
			})
		})
	}
	return out
}

func stringConstants(file *ast.File) map[string]string {
	out := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				if i >= len(valueSpec.Values) {
					continue
				}
				if value, ok := environmentKey(valueSpec.Values[i], nil); ok {
					out[name.Name] = value
				}
			}
		}
	}
	return out
}

func environmentKey(expr ast.Expr, constants map[string]string) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		name, err := strconv.Unquote(value.Value)
		return name, err == nil
	case *ast.Ident:
		name, ok := constants[value.Name]
		return name, ok
	default:
		return "", false
	}
}

var envReaderNames = map[string]bool{
	"Getenv": true, "LookupEnv": true,
	"getenv": true, "getbool": true, "getduration": true, "getint": true, "getint64": true,
	"envOr": true, "envDuration": true,
}

func isEnvReader(fun ast.Expr) bool {
	switch expr := fun.(type) {
	case *ast.SelectorExpr:
		return envReaderNames[expr.Sel.Name]
	case *ast.Ident:
		return envReaderNames[expr.Name]
	default:
		return false
	}
}

func walkProductionGoFiles(t *testing.T, dir string, visit func(path string)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "node_modules" || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			visit(path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

// allEnvMentions collects every SYNAPSE_* literal anywhere in the Go tree, tests included, so a stale
// exclusion can be distinguished from a test-only variable.
func allEnvMentions(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, dir := range []string{"internal", "cmd"} {
		walkGoFiles(t, filepath.Join(root, dir), true, func(_, content string) {
			for _, match := range envLiteral.FindAllStringSubmatch(content, -1) {
				out[match[1]] = true
			}
		})
	}
	return out
}

// walkGoFiles visits every .go file under dir, optionally including _test.go files.
func walkGoFiles(t *testing.T, dir string, includeTests bool, visit func(rel, content string)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "node_modules" || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !includeTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		visit(filepath.ToSlash(path), string(data))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
