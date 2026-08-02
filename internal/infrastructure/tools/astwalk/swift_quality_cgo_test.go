//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func swiftFixtureFindings(t *testing.T, source string) []QualityFinding {
	t.Helper()
	root := parseRoot(context.Background(), specs["Swift"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatalf("Swift fixture is not syntactically complete: %q", source)
	}
	findings, _ := swiftFindings(root, []byte(source), "fixture.swift")
	return findings
}

func swiftRules(findings []QualityFinding) []string {
	rules := make([]string, 0, len(findings))
	for _, finding := range findings {
		rules = append(rules, finding.Rule)
	}
	sort.Strings(rules)
	return rules
}

var swiftASTKeys = []string{
	"force-unwrap", "force-try", "force-cast", "array-index-literal", "dictionary-force-lookup", "fatal-error", "precondition-failure", "try-optional-discard", "empty-switch-case", "constant-condition", "duplicate-switch-case", "self-assignment", "comparison-self", "invalid-range", "integer-division", "nil-coalescing-self", "redundant-optional-bind", "unreachable-after-return", "empty-catch", "return-in-defer", "assert-production", "implicitly-unwrapped-local", "optional-equality-nil", "guard-without-exit", "duplicate-dictionary-key", "broad-catch", "error-discarded", "empty-defer", "throw-generic-error", "catch-print-only", "error-message-lost", "retain-cycle-self", "implicitly-unwrapped-optional", "notification-observer-unremoved", "timer-retain-cycle", "file-handle-unclosed", "dispatch-source-unbalanced", "autoreleasepool-missing", "unsafe-pointer-escape", "task-unstructured", "task-sleep-error-discarded", "main-queue-sync", "semaphore-wait-main", "continuation-resume-missing", "detached-task-self", "actor-blocking-call", "lock-with-await", "dispatch-group-wait", "operation-queue-main-block", "sql-concat", "command-shell", "path-concat", "url-interpolation", "predicate-format", "html-string", "unsafe-deserialization", "regex-from-input", "weak-hash", "insecure-random", "ecb-mode", "hardcoded-key", "static-iv", "tls-trust-all", "http-url", "webview-javascript", "pasteboard-sensitive", "keychain-accessible-always", "biometric-fallback", "debug-server", "sensitive-log", "print-logging", "nsurl-legacy", "nsdata-legacy", "nsstring-legacy", "dispatch-once", "uiapplication-openurl", "string-size", "selector-string", "perform-selector", "kvc-string", "notification-string-name", "userdefaults-sensitive", "bundle-path", "foundation-date-formatter", "deprecated-availability", "any-without-protocol", "anyobject-cast", "implicitly-unwrapped-parameter", "raw-value-enum-string", "tuple-return-many", "optional-boolean", "stringly-typed-key", "type-erasure-cast", "objc-dynamic", "inout-escaping", "protocol-composition-long", "metatype-cast", "optional-collection", "existential-any", "opaque-result-erased", "array-contains-loop", "string-concat-loop", "map-filter-chain", "sort-first", "count-zero", "repeated-dateformatter", "data-copy", "main-thread-heavy-loop", "long-function", "large-type", "deep-nesting", "too-many-parameters", "todo-comment", "commented-code", "magic-number", "single-letter-name", "public-undocumented", "redundant-self",
}

func TestSwiftGrammarContractReachability(t *testing.T) {
	const source = `
actor Worker { func wait(_ lock: NSLock) { lock.lock() } }
func f(_ value: AnyObject) {
  let item = [1][0]
  var token: String!
  defer { return }
  throw NSError(domain: "App", code: 1)
}`
	root := parseRoot(context.Background(), specs["Swift"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatal("Swift grammar did not parse contract fixture")
	}
	seen := map[string]bool{}
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		seen[n.Type()] = true
		for i := 0; i < int(n.ChildCount()); i++ {
			stack = append(stack, n.Child(i))
		}
	}
	for _, want := range []string{"call_expression", "call_suffix", "simple_identifier", "navigation_expression", "lambda_literal", "value_argument", "property_declaration", "statements", "control_transfer_statement", "class_declaration"} {
		if !seen[want] {
			t.Errorf("bundled Swift grammar lacks reachable %q: %v", want, seen)
		}
	}
	for _, absent := range []string{"postfix_expression", "subscript_expression", "local_declaration", "variable_declaration", "defer_statement", "throw_statement", "actor_declaration"} {
		if seen[absent] {
			t.Errorf("detector must not rely on unavailable Swift grammar node %q", absent)
		}
	}
}

func TestSwiftRuntimeKeyRegistryCompleteness(t *testing.T) {
	if len(swiftASTKeys) != 118 {
		t.Fatalf("Swift AST key inventory = %d, want 118", len(swiftASTKeys))
	}
	got := make(map[string]bool, len(swiftRuntimeRules))
	for key := range swiftRuntimeRules {
		got[key] = true
	}
	for _, key := range swiftASTKeys {
		if !got[key] {
			t.Errorf("Swift runtime registry missing %q", key)
		}
		delete(got, key)
	}
	for key := range got {
		t.Errorf("Swift runtime registry has untracked key %q", key)
	}
}

func TestSwiftASTCatalogExamples(t *testing.T) {
	catalog, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("catalog.List(): %v", err)
	}
	for _, catalogRule := range rules {
		if catalogRule.Language != "Swift" || catalogRule.Detection != rule.DetectionAST {
			continue
		}
		key := string(catalogRule.Key)
		t.Run(strings.TrimPrefix(key, "swift:"), func(t *testing.T) {
			noncompliant := swiftExampleProgram(catalogRule.NoncompliantExample)
			if root := parseRoot(context.Background(), specs["Swift"], []byte(noncompliant)); root == nil || root.HasError() {
				t.Fatalf("noncompliant catalog example is not syntactically complete: %q", noncompliant)
			}
			if !swiftHasRule(swiftCompleteFixtureFindings(t, noncompliant), key) {
				t.Fatalf("noncompliant catalog example did not emit %s: %q", key, catalogRule.NoncompliantExample)
			}
			compliant := swiftExampleProgram(catalogRule.CompliantExample)
			if root := parseRoot(context.Background(), specs["Swift"], []byte(compliant)); root == nil || root.HasError() {
				t.Fatalf("compliant catalog example is not syntactically complete: %q", compliant)
			}
			if swiftHasRule(swiftCompleteFixtureFindings(t, compliant), key) {
				t.Fatalf("compliant catalog example emitted %s: %q", key, catalogRule.CompliantExample)
			}
		})
	}
}

func swiftExampleProgram(example string) string {
	trimmed := strings.TrimSpace(example)
	if strings.HasPrefix(trimmed, "@available") {
		return trimmed + "\nfunc fixture() {}"
	}
	if strings.HasPrefix(trimmed, "///") && strings.Contains(trimmed, "func ") {
		return trimmed
	}
	if strings.HasPrefix(trimmed, "static ") {
		return "struct Fixture { " + trimmed + " }"
	}
	if strings.HasPrefix(trimmed, "var delegate:") || strings.HasPrefix(trimmed, "@objc dynamic") {
		return "class Fixture { " + trimmed + " }"
	}
	if strings.HasPrefix(trimmed, "options:") {
		return "func fixture() { cipher(" + trimmed + ") }"
	}
	if strings.HasPrefix(trimmed, "kSecAttrAccessible:") {
		return "func fixture() { let options = [" + trimmed + "] }"
	}
	if strings.HasPrefix(trimmed, "self.") {
		return "class Fixture { var name = \"\"; func fixture(_ value: String) { " + trimmed + " } }"
	}
	if strings.HasPrefix(trimmed, "func ") || strings.HasPrefix(trimmed, "public func ") {
		if strings.Contains(trimmed, "{") {
			return trimmed
		}
		return trimmed + " {}"
	}
	if strings.HasPrefix(trimmed, "class ") || strings.HasPrefix(trimmed, "struct ") || strings.HasPrefix(trimmed, "actor ") || strings.HasPrefix(trimmed, "enum ") || strings.HasPrefix(trimmed, "protocol ") {
		return trimmed
	}
	if strings.HasPrefix(trimmed, "catch ") {
		return "func fixture() throws { do { try work() } " + trimmed + " }"
	}
	if strings.HasPrefix(trimmed, "if let _ = user") {
		return "func fixture(_ user: String?) { " + trimmed + " }"
	}
	if strings.HasPrefix(trimmed, "for item in input") {
		return "func fixture(_ input: [Int], _ items: [Int]) { " + trimmed + " }"
	}
	if strings.HasPrefix(trimmed, "let best = items.sorted") {
		return "func fixture(_ items: [Int]) { " + trimmed + " }"
	}
	if strings.HasPrefix(trimmed, "case ") {
		return "func fixture(_ value: Int) { switch value { " + trimmed + " default: break } }"
	}
	if strings.HasPrefix(trimmed, "defer ") {
		return "func fixture() { " + trimmed + " }"
	}
	if trimmed == "lock.lock()" {
		return "actor Fixture { func run(_ lock: NSLock) { " + trimmed + " } }"
	}
	return "func fixture(_ value: AnyObject, _ items: [Int], _ headers: [String: String], _ input: String, _ enabled: Bool, _ name: String, _ password: String, _ userID: String? = nil, _ data: Data = Data()) throws {\n" + example + "\n}"
}

func TestSwiftRuntimeCatalogParity(t *testing.T) {
	catalog, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("catalog.List(): %v", err)
	}
	catalogRules := map[string]rule.Rule{}
	for _, catalogRule := range rules {
		if catalogRule.Language == "Swift" && catalogRule.Detection == rule.DetectionAST {
			catalogRules[string(catalogRule.Key)] = catalogRule
		}
	}
	if len(catalogRules) != 118 {
		t.Fatalf("Swift AST catalog rules = %d, want 118", len(catalogRules))
	}
	if len(swiftRuntimeRules) != len(catalogRules) {
		t.Fatalf("Swift runtime rules = %d, want %d", len(swiftRuntimeRules), len(catalogRules))
	}
	for _, runtime := range swiftRuntimeRules {
		catalogRule, ok := catalogRules[runtime.rule]
		if !ok {
			t.Fatalf("runtime rule %q is absent from the AST catalog", runtime.rule)
		}
		wantKind := "quality"
		if catalogRule.Type == rule.TypeBug && catalogRule.Qualities[0] == rule.QualityReliability {
			wantKind = "reliability"
		} else if catalogRule.Type == rule.TypeVulnerability || catalogRule.Type == rule.TypeSecurityHotspot || catalogRule.Qualities[0] == rule.QualitySecurity {
			wantKind = "sast"
		}
		if runtime.kind != wantKind || runtime.title != catalogRule.Name || runtime.severity != string(catalogRule.DefaultSeverity) {
			t.Fatalf("metadata mismatch for %s: runtime=%+v catalog=%+v", runtime.rule, runtime, catalogRule)
		}
		cwe := ""
		if len(catalogRule.CWE) > 0 {
			cwe = catalogRule.CWE[0]
		}
		if runtime.cwe != cwe {
			t.Fatalf("CWE mismatch for %s: runtime=%q catalog=%q", runtime.rule, runtime.cwe, cwe)
		}
	}
}

func TestSwiftTokenLocalAmbiguityNegatives(t *testing.T) {
	findings := swiftFixtureFindings(t, `
func check(_ enabled: Bool, _ left: Int, _ right: Int) {
  if !enabled || left != right { print("diagnostic") }
  let value = try? load()
  let title = input as? String
}`)
	for _, unexpected := range []string{"swift:force-unwrap", "swift:force-try", "swift:force-cast"} {
		for _, got := range swiftRules(findings) {
			if got == unexpected {
				t.Fatalf("unexpected %s from ambiguity-negative fixture: %+v", unexpected, findings)
			}
		}
	}
}

func TestSwiftCommentsAndMalformedSiblingRecovery(t *testing.T) {
	source := []byte(`
// TODO: remove compatibility fallback
// let legacy = oldValue
let valid = value!
let malformed = (
print("diagnostic")
`)
	root := parseRoot(context.Background(), specs["Swift"], source)
	if root == nil || !root.HasError() {
		t.Fatal("malformed sibling fixture must produce an error root")
	}
	findings, _ := swiftFindings(root, source, "fixture.swift")

	got := swiftRules(findings)
	for _, want := range []string{"swift:todo-comment", "swift:commented-code", "swift:force-unwrap", "swift:print-logging"} {
		found := false
		for _, actual := range got {
			if actual == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %s after malformed sibling: %+v", want, findings)
		}
	}
}

func TestSwiftQualityForMalformedSiblingIsTruncated(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "mixed.swift", `let valid = value!
let malformed = (
print("diagnostic")
`)

	quality, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	if !quality.Truncated {
		t.Fatal("QualityFor must mark parser recovery as truncated")
	}
	for _, finding := range quality.Findings {
		if finding.Rule == "swift:force-unwrap" && finding.File == "mixed.swift" {
			return
		}
	}
	t.Fatalf("QualityFor dropped valid Swift sibling findings: %+v", quality.Findings)
}

func TestSwiftQualityForDispatchLineAndIsolation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "source.swift", "let value = input!\r\n")
	writeFile(t, root, "other.py", "value = input!\n")
	quality, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	if len(quality.Findings) != 1 || quality.Findings[0].Rule != "swift:force-unwrap" || quality.Findings[0].File != "source.swift" || quality.Findings[0].Line != 1 {
		t.Fatalf("Swift dispatch/line/isolation findings = %+v", quality.Findings)
	}
}

func TestSwiftQualityForAggregateTotalCap(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 6; i++ {
		var source strings.Builder
		for j := 0; j < 20; j++ {
			source.WriteString("fatalError(\"stop\")\n")
		}
		writeFile(t, root, fmt.Sprintf("capped-%d.swift", i), source.String())
	}
	quality, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	if len(quality.Findings) != maxSwiftPerRule || !quality.Truncated {
		t.Fatalf("Swift aggregate cap findings=%d truncated=%t, want %d and true", len(quality.Findings), quality.Truncated, maxSwiftPerRule)
	}
}

func TestSwiftQualityForTotalCap(t *testing.T) {
	root := t.TempDir()
	var source strings.Builder
	for i := 0; i < 101; i++ {
		source.WriteString("fatalError(\"stop\")\n")
	}
	writeFile(t, root, "capped.swift", source.String())
	quality, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	if len(quality.Findings) != maxSwiftPerRule || !quality.Truncated {
		t.Fatalf("Swift total cap findings=%d truncated=%t, want %d and true", len(quality.Findings), quality.Truncated, maxSwiftPerRule)
	}
}

func TestSwiftTaskCalleeAndTryContexts(t *testing.T) {
	findings := swiftFixtureFindings(t, `
func f() async {
  let task = Task { await refresh() }
  Task.detached { await refresh() }
  await withCheckedContinuation { continuation in continuation.resume() }
  let saved = try? save()
  return try? load()
  consume(try? read())
}`)
	for _, unwanted := range []string{"swift:task-unstructured", "swift:try-optional-discard"} {
		if swiftHasRule(findings, unwanted) {
			t.Fatalf("unexpected %s: %+v", unwanted, findings)
		}
	}
	if swiftHasRule(findings, "swift:continuation-resume-missing") {
		t.Fatalf("unexpected continuation finding after local resume: %+v", findings)
	}
}

func TestSwiftTraversalCaps(t *testing.T) {
	root := parseRoot(context.Background(), specs["Swift"], []byte("func f() { fatalError(\"stop\") }"))
	for name, caps := range map[string]swiftCaps{
		"nodes":      {depth: maxSwiftDepth, nodes: 1, work: maxSwiftWork, candidates: maxSwiftCandidates},
		"work":       {depth: maxSwiftDepth, nodes: maxSwiftNodes, work: 1, candidates: maxSwiftCandidates},
		"depth":      {depth: 0, nodes: maxSwiftNodes, work: maxSwiftWork, candidates: maxSwiftCandidates},
		"candidates": {depth: maxSwiftDepth, nodes: maxSwiftNodes, work: maxSwiftWork, candidates: 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, truncated := swiftFindingsLimitWithCaps(root, []byte("func f() { fatalError(\"stop\") }"), "fixture.swift", maxSwiftTotal, nil, caps)
			if !truncated {
				t.Fatal("Swift traversal cap must mark analysis truncated")
			}
		})
	}
}

func TestSwiftFindingsDeterministicAndCapped(t *testing.T) {
	source := ""
	for i := 0; i < 40; i++ {
		source += "let value = input!\n"
	}
	first := swiftFixtureFindings(t, source)
	if count := len(first); count != maxSwiftPerRule {
		t.Fatalf("force unwrap findings = %d, want cap %d", count, maxSwiftPerRule)
	}
	for i := 0; i < 10; i++ {
		got := swiftFixtureFindings(t, source)
		if len(got) != len(first) {
			t.Fatalf("run %d findings = %d, want %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("run %d finding %d differs: got=%+v want=%+v", i, j, got[j], first[j])
			}
		}
	}
}

func TestSwiftFocusedDetectorRegressions(t *testing.T) {
	assertRule := func(t *testing.T, source, rule string, want bool) {
		t.Helper()
		got := swiftHasRule(swiftFixtureFindings(t, source), rule)
		if got != want {
			t.Fatalf("%s finding = %t, want %t: %s", rule, got, want, source)
		}
	}
	t.Run("IUO negatives", func(t *testing.T) {
		assertRule(t, `func f(_ left: Int, _ right: Int, _ value: Int?) { let unwrapped = value!; if !enabled || left != right {} }`, "swift:implicitly-unwrapped-local", false)
	})
	t.Run("guard exits", func(t *testing.T) {
		assertRule(t, `func f(_ enabled: Bool) { guard enabled else { return "disabled" } }`, "swift:guard-without-exit", false)
		assertRule(t, `func f(_ enabled: Bool) { guard enabled else { if enabled { return } } }`, "swift:guard-without-exit", true)
		assertRule(t, `func f(_ enabled: Bool) { guard enabled else { return }; work() }`, "swift:unreachable-after-return", false)
	})
	t.Run("process shell flow", func(t *testing.T) {
		assertRule(t, `func f(_ input: String) { let command = input; let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/sh"); process.arguments = ["-c", command] }`, "swift:command-shell", true)
		assertRule(t, `func f() { let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/sh"); process.arguments = ["-c", "date"] }`, "swift:command-shell", false)
		assertRule(t, `func f(_ input: String) { let command = input; let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/git"); process.arguments = ["-c", command] }`, "swift:command-shell", false)
	})
	t.Run("hardcoded key message", func(t *testing.T) {
		assertRule(t, `let errorMessage = "key unavailable"`, "swift:hardcoded-key", false)
		assertRule(t, `let secretaryName = "Ada"`, "swift:hardcoded-key", false)
	})
	t.Run("integer range without overflow", func(t *testing.T) {
		assertRule(t, `func f() { for value in 184467440737095516160...184467440737095516159 { use(value) } }`, "swift:invalid-range", true)
	})
	t.Run("trailing closures", func(t *testing.T) {
		assertRule(t, `class Owner { func f() { Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in self.tick() } }; func tick() {} }`, "swift:timer-retain-cycle", true)
		assertRule(t, `class Owner { func f() { Task.detached { self.refresh() } }; func refresh() {} }`, "swift:detached-task-self", true)
	})
	t.Run("structural call arguments", func(t *testing.T) {
		assertRule(t, `func f(_ id: String) { query(sql: "SELECT * FROM users WHERE id = \(id)", options: ["a,b"]) }`, "swift:sql-concat", true)
		assertRule(t, `func f(_ id: String) { query(sql: "SELECT * FROM users WHERE id = ?", options: ["a,b"]) }`, "swift:sql-concat", false)
		assertRule(t, `func f(_ items: [Int]) { let first = items[0] }`, "swift:array-index-literal", true)
	})
	t.Run("exact types and security constants", func(t *testing.T) {
		assertRule(t, `func f(_ value: Any?) { use(value) }`, "swift:any-without-protocol", false)
		assertRule(t, `func f(_ value: Any) { use(value) }`, "swift:any-without-protocol", true)
		assertRule(t, `func f() -> Any? { return nil }`, "swift:opaque-result-erased", false)
		assertRule(t, `func f() -> Any { return 1 }`, "swift:opaque-result-erased", true)
		assertRule(t, `func f() { let nonce = Data(repeating: 7, count: 16) }`, "swift:static-iv", true)
		assertRule(t, `func f() { let apiKey = "changeme" }`, "swift:hardcoded-key", false)
		assertRule(t, `func f() { let apiKey = "0123456789abcdef" }`, "swift:hardcoded-key", true)
		assertRule(t, `func f() { let sessionToken = drand48() }`, "swift:insecure-random", true)
	})
	t.Run("callable scopes and control bodies", func(t *testing.T) {
		assertRule(t, `class C { init() { let formatter = DateFormatter() } }`, "swift:repeated-dateformatter", true)
		assertRule(t, `func f() { if a { if b { if c { if d { if e { run() } } } } } }`, "swift:deep-nesting", true)
		assertRule(t, `func f() { switch value { case 1: run(); case 1: again(); default: run() } }`, "swift:duplicate-switch-case", true)
	})
	t.Run("LAContext instance", func(t *testing.T) {
		assertRule(t, `func f() { let context = LAContext(); context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock") }`, "swift:biometric-fallback", true)
	})
	t.Run("continuation multiline resume", func(t *testing.T) {
		assertRule(t, "func f() async { await withCheckedContinuation { continuation in\n continuation\n .resume(returning: 1)\n} }", "swift:continuation-resume-missing", false)
	})
	t.Run("function header only", func(t *testing.T) {
		findings := swiftFixtureFindings(t, "func outer() {\nfunc nested(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int, h: Int) {}\n}")
		for _, finding := range findings {
			if finding.Rule != "swift:too-many-parameters" {
				continue
			}
			if finding.Line == 1 {
				t.Fatal("outer function header must not emit too-many-parameters")
			}
		}
		if !swiftHasRule(findings, "swift:too-many-parameters") {
			t.Fatal("nested function must emit too-many-parameters")
		}
	})
	t.Run("long structural declarations", func(t *testing.T) {
		assertRule(t, "func f() {\n"+strings.Repeat("work()\n", 1800)+"}", "swift:long-function", true)
	})
	t.Run("threshold boundaries", func(t *testing.T) {
		var function, members, nested strings.Builder
		function.WriteString("func f() {\n")
		for i := 0; i < 50; i++ {
			function.WriteString("work()\n")
		}
		function.WriteString("}\n")
		assertRule(t, function.String(), "swift:long-function", false)
		members.WriteString("class C {\n")
		for i := 0; i < 40; i++ {
			fmt.Fprintf(&members, "let value%d = 0\n", i)
		}
		members.WriteString("}\n")
		assertRule(t, members.String(), "swift:large-type", false)
		nested.WriteString("func f() { if a { if b { if c { if d { work() } } } } }")
		assertRule(t, nested.String(), "swift:deep-nesting", false)
	})
}

func TestSwiftDictionaryLookupDedupeAndRepositoryCap(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&source, "let value%d = headers[\"key%d\"]!\n", i, i)
	}
	findings := swiftFixtureFindings(t, source.String())
	count := 0
	lines := map[int]bool{}
	for _, finding := range findings {
		if finding.Rule == "swift:dictionary-force-lookup" {
			count++
			lines[finding.Line] = true
		}
	}
	if count != maxSwiftPerRule || len(lines) != maxSwiftPerRule {
		t.Fatalf("dictionary lookup findings=%d unique lines=%d, want %d: %+v", count, len(lines), maxSwiftPerRule, findings)
	}

	root := t.TempDir()
	for i := 0; i < 2; i++ {
		var file strings.Builder
		for j := 0; j < 15; j++ {
			fmt.Fprintf(&file, "let value%d = headers[\"key%d\"]!\n", j, j)
		}
		writeFile(t, root, fmt.Sprintf("file%d.swift", i), file.String())
	}
	quality, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	count = 0
	for _, finding := range quality.Findings {
		if finding.Rule == "swift:dictionary-force-lookup" {
			count++
		}
	}
	if count != maxSwiftPerRule || !quality.Truncated {
		t.Fatalf("repository dictionary lookup findings=%d truncated=%t, want %d and true", count, quality.Truncated, maxSwiftPerRule)
	}
}
