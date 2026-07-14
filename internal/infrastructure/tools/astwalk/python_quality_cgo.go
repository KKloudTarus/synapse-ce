//go:build cgo

package astwalk

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

type pythonRule struct {
	kind, id, cwe, severity, title, description string
}

var pythonRules = map[string]pythonRule{
	"mutable-default":    {"reliability", "python-mutable-default-argument", "CWE-398", "high", "Mutable default argument", "A mutable default value is shared by every call. Use None and create the value inside the function."},
	"bare-except":        {"reliability", "python-bare-except", "CWE-396", "medium", "Bare except catches every exception", "Catching every exception can hide unexpected failures. Catch the expected exception type instead."},
	"return-finally":     {"reliability", "python-return-in-finally", "CWE-584", "medium", "Control flow in finally suppresses exceptions", "Returning or breaking from finally can discard an active exception or return value."},
	"duplicate-dict":     {"reliability", "python-duplicate-dict-key", "CWE-561", "medium", "Duplicate dictionary key", "A later dictionary entry overwrites an earlier entry with the same literal key."},
	"assert":             {"sast", "python-assert-for-validation", "CWE-617", "medium", "Runtime assert used for validation", "Assertions can be disabled at runtime. Raise an explicit exception for input validation."},
	"none":               {"quality", "python-eq-none", "", "low", "Compare None with is", "Use is None or is not None for singleton identity checks."},
	"star-import":        {"quality", "python-star-import", "", "low", "Wildcard import", "Wildcard imports hide a module's dependencies and can overwrite names."},
	"open":               {"quality", "python-open-no-context", "", "low", "File opened without a context manager", "Use with open(...) so the file closes reliably when an error occurs."},
	"type-eq":            {"quality", "python-type-eq-vs-isinstance", "", "low", "Use isinstance instead of type equality", "isinstance supports subclasses while a direct type comparison does not."},
	"global":             {"quality", "python-global-statement", "", "low", "Global statement", "Global state makes data flow harder to understand and test."},
	"args":               {"quality", "python-too-many-args", "", "low", "Function has too many arguments", "A long parameter list makes an API hard to call and evolve. Group related values into an object."},
	"f-log":              {"quality", "python-f-string-logging", "", "info", "Eager f-string logging", "Use logger parameter formatting so message construction is deferred when the log level is disabled."},
	"len-zero":           {"quality", "python-len-eq-zero", "", "info", "Compare a collection directly", "Use collection truthiness instead of comparing len(collection) to zero."},
	"unused-import":      {"quality", "python-unused-import", "", "info", "Unused import", "Remove imports that are not referenced by the module."},
	"broad-raise":        {"quality", "python-broad-raise", "", "low", "Broad Exception raised", "Raise a specific exception type so callers can handle the failure deliberately."},
	"is-literal":         {"reliability", "python-is-literal", "CWE-480", "medium", "Identity check against a literal", "`is` compares object identity, not value; comparing to a literal is unreliable (CPython caches only some small values). Use ==."},
	"broad-except":       {"reliability", "python-broad-except", "CWE-396", "medium", "Broad except clause", "Catching Exception/BaseException traps almost every error, including bugs. Catch the specific exception types the code can recover from."},
	"lambda-assign":      {"quality", "python-lambda-assignment", "", "low", "Lambda assigned to a variable", "Binding a lambda to a name gives it a worse repr and traceback than a def; use a def statement."},
	"multi-import":       {"quality", "python-multiple-imports", "", "low", "Multiple imports on one line", "Importing several modules in one statement is harder to read and diff. Put each import on its own line."},
	"fstring-empty":      {"quality", "python-fstring-no-placeholder", "", "info", "f-string without placeholders", "An f-string with no {…} placeholder is just a string literal; drop the f prefix."},
	"subprocess-shell":   {"sast", "python-subprocess-shell", "CWE-78", "high", "subprocess with shell=True", "shell=True runs the command through a shell, so any input in the command string can inject OS commands. Pass an argument list and shell=False."},
	"shadow-builtin":     {"quality", "python-shadow-builtin", "", "low", "Shadowing a builtin name", "Reassigning a builtin (list, dict, id, ...) hides it for the rest of the scope. Use a different name."},
	"assert-tuple":       {"reliability", "python-assert-tuple", "CWE-571", "high", "Assert on a tuple is always true", "assert (a, b) tests a non-empty tuple, which is always truthy, so the assertion never fails. Use `assert a, b` or separate asserts."},
	"bind-all":           {"sast", "python-bind-all-interfaces", "CWE-605", "medium", "Bind to all network interfaces", "Binding to 0.0.0.0 exposes the service on every interface, including untrusted networks. Bind to a specific address."},
	"mktemp":             {"sast", "python-mktemp-insecure", "CWE-377", "medium", "Insecure tempfile.mktemp", "mktemp only returns a name, leaving a race window before the file is created. Use mkstemp or NamedTemporaryFile."},
	"yaml-unsafe":        {"sast", "python-yaml-unsafe-load", "CWE-502", "high", "Unsafe yaml.load", "yaml.load with the default loader can construct arbitrary Python objects from untrusted input. Use yaml.safe_load."},
	"return-in-init":     {"reliability", "python-return-in-init", "", "low", "Return value in __init__", "__init__ must return None; returning a value raises TypeError at call time."},
	"long-function":      {"quality", "python-too-long-function", "", "low", "Overly long function", "A function with a very large number of statements is hard to understand and test; split it into smaller functions."},
	"mutable-class-attr": {"reliability", "python-mutable-class-attribute", "", "medium", "Mutable class attribute", "A class attribute assigned a list/dict/set literal is shared across all instances; assign it in __init__ instead."},
	"nested-conditional": {"quality", "python-nested-conditional", "", "low", "Nested conditional expression", "A conditional expression inside another is hard to read; use an if/else statement."},
	"large-class":        {"quality", "python-large-class", "", "low", "Class has too many methods", "A class with a very large number of methods likely has too many responsibilities; consider splitting it."},
	"compare-empty":      {"quality", "python-compare-empty-collection", "", "low", "Comparison to an empty collection", "Comparing to [] / {} / () is less clear than a truthiness check; use `if not x`."},
	"except-pass":        {"reliability", "python-except-pass", "CWE-390", "low", "Exception silently passed", "An except whose only statement is pass swallows the error with no handling or logging."},
	"compare-bool":       {"quality", "python-compare-bool-literal", "", "low", "Comparison to a boolean literal", "Comparing to True/False is redundant; use the value directly (or `not value`)."},
	"too-many-returns":   {"quality", "python-too-many-returns", "", "low", "Function has too many return statements", "A function with many return points is hard to follow; simplify the control flow."},
	"deep-nesting":       {"quality", "python-deep-nesting", "", "medium", "Deeply nested control flow", "Control flow nested more than four levels deep is hard to read and test; use guard clauses or extract functions."},
	"nested-loop":        {"quality", "python-nested-loop", "", "medium", "Deeply nested loops", "Three or more loops nested inside each other are hard to follow and often costly; extract or rethink them."},
	"complex-condition":  {"quality", "python-complex-condition", "", "low", "Overly complex boolean condition", "A condition combining many and/or operators is hard to reason about; name the sub-conditions."},
	"high-complexity":    {"quality", "python-high-complexity", "", "medium", "Function has high cyclomatic complexity", "A function with many decision points (if/elif/loop/except/and/or) is hard to test; reduce branching or split it."},
}

// pyControlTypes / pyLoopTypes are the node kinds counted for nesting-depth metrics.
var pyControlTypes = map[string]bool{
	"if_statement": true, "for_statement": true, "while_statement": true, "try_statement": true, "with_statement": true,
}
var pyLoopTypes = map[string]bool{"for_statement": true, "while_statement": true}

var emptyCompareRE = regexp.MustCompile(`(?s)(==|!=)\s*(\[\s*\]|\{\s*\}|\(\s*\))|(\[\s*\]|\{\s*\})\s*(==|!=)`)
var boolCompareRE = regexp.MustCompile(`(?s)(==|!=)\s*(True|False)\b|\b(True|False)\s*(==|!=)`)

// pyMaxDepthByType returns the maximum nesting depth of nodes whose type is in types within n's
// subtree (each matching node adds one level). Used for control-flow and loop nesting metrics.
func pyMaxDepthByType(n *sitter.Node, types map[string]bool) int {
	best := 0
	for i := 0; i < int(n.ChildCount()); i++ {
		if d := pyMaxDepthByType(n.Child(i), types); d > best {
			best = d
		}
	}
	if types[n.Type()] {
		return best + 1
	}
	return best
}

// pyCountBoolOps counts the boolean_operator nodes (and/or) in n's subtree (condition complexity).
func pyCountBoolOps(n *sitter.Node) int {
	count := 0
	if n.Type() == "boolean_operator" {
		count++
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		count += pyCountBoolOps(n.Child(i))
	}
	return count
}

// pyComplexity approximates cyclomatic complexity by counting decision points in n's subtree.
func pyComplexity(n *sitter.Node) int {
	c := 0
	switch n.Type() {
	case "if_statement", "elif_clause", "for_statement", "while_statement", "except_clause",
		"conditional_expression", "boolean_operator", "case_clause":
		c++
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		c += pyComplexity(n.Child(i))
	}
	return c
}

// countReturnsBounded counts return_statement nodes under body without descending into nested scopes
// (functions/lambdas/classes) named in stop. Shared by the Python/Java/JS quality walkers.
func countReturnsBounded(body *sitter.Node, stop map[string]bool) int {
	if body == nil {
		return 0
	}
	cnt := 0
	stack := []*sitter.Node{body}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c.Type() == "return_statement" {
			cnt++
		}
		if c != body && stop[c.Type()] {
			continue
		}
		for i := 0; i < int(c.ChildCount()); i++ {
			stack = append(stack, c.Child(i))
		}
	}
	return cnt
}

// pyHasDescendantType reports whether n has a descendant (excluding itself) of the given type.
func pyHasDescendantType(n *sitter.Node, typ string) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		ch := n.Child(i)
		if ch.Type() == typ || pyHasDescendantType(ch, typ) {
			return true
		}
	}
	return false
}

// pyExceptOnlyPass reports whether an except_clause's body is a single pass statement.
func pyExceptOnlyPass(n *sitter.Node) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c.Type() == "block" {
			return c.NamedChildCount() == 1 && c.NamedChild(0).Type() == "pass_statement"
		}
	}
	return false
}

// pyInitReturnsValue reports whether a function body contains a return statement with a value,
// without descending into nested function/class definitions.
func pyInitReturnsValue(fn *sitter.Node) bool {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return false
	}
	stack := []*sitter.Node{body}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c.Type() == "return_statement" && c.NamedChildCount() > 0 {
			return true
		}
		if c != body && (c.Type() == "function_definition" || c.Type() == "class_definition") {
			continue // do not descend into nested scopes
		}
		for i := 0; i < int(c.ChildCount()); i++ {
			stack = append(stack, c.Child(i))
		}
	}
	return false
}

var (
	noneCompareRE     = regexp.MustCompile(`(?s)(==|!=)\s*None\b|\bNone\s*(==|!=)`)
	typeCompareRE     = regexp.MustCompile(`(?s)\btype\s*\([^)]*\)\s*(==|!=)`)
	lenZeroRE         = regexp.MustCompile(`(?s)\blen\s*\([^)]*\)\s*(==|!=)\s*0\b|\b0\s*(==|!=)\s*len\s*\(`)
	fStringRE         = regexp.MustCompile(`(?s)\bf["']`)
	broadRaiseRE      = regexp.MustCompile(`(?s)^\s*raise\s+(Exception|BaseException)\s*(\(|$)`)
	isLiteralRE       = regexp.MustCompile(`(?s)\bis\s+(not\s+)?(-?[0-9]|['"]|\[|\()`)
	broadExceptRE     = regexp.MustCompile(`(?s)^\s*except\s+(Exception|BaseException)\b`)
	lambdaAssignRE    = regexp.MustCompile(`(?s)^\s*[A-Za-z_]\w*\s*(:[^=]+)?=\s*lambda\b`)
	multiImportRE     = regexp.MustCompile(`(?s)^\s*import\s+[^\n,]+,`)
	fStringEmptyRE    = regexp.MustCompile(`(?s)^[rR]?[fF][rR]?["']`)
	subprocessShellRE = regexp.MustCompile(`(?s)\bshell\s*=\s*True\b`)
	builtinShadowRE   = regexp.MustCompile(`(?s)^\s*(list|dict|set|str|int|float|bool|id|type|input|max|min|sum|len|filter|map|next|iter|open|vars|dir|hash|bytes|object)\s*=\s*[^=]`)
	assertTupleRE     = regexp.MustCompile(`(?s)^\s*assert\s*\([^)]*,[^)]*\)`)
	bindAllRE         = regexp.MustCompile(`(?s)['"]0\.0\.0\.0['"]`)
	mktempRE          = regexp.MustCompile(`(?s)\btempfile\.mktemp\s*\(|\bmktemp\s*\(`)
	yamlLoadRE        = regexp.MustCompile(`(?s)\byaml\.load\s*\(`)
)

// QualityFor parses Python files and returns the precision-biased seed quality rules. It deliberately does
// not attempt alias, import-resolution, or interprocedural analysis.
func QualityFor(ctx context.Context, root string) (Quality, error) {
	out := Quality{Findings: []QualityFinding{}}
	truncated, err := walkSource(ctx, root, func(rel, lang string, content []byte) {
		if lang != "Python" && lang != "Java" && lang != "JavaScript" {
			return
		}
		tree := parseRoot(ctx, specs[lang], content)
		if tree == nil {
			return
		}
		switch lang {
		case "Python":
			out.Findings = append(out.Findings, pythonFindings(tree, content, rel)...)
		case "Java":
			out.Findings = append(out.Findings, javaFindings(tree, content, rel)...)
		case "JavaScript":
			out.Findings = append(out.Findings, jsFindings(tree, content, rel)...)
		}
	})
	if err != nil {
		return Quality{}, err
	}
	out.Truncated = truncated
	sort.Slice(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return out, nil
}

func pythonFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	var out []QualityFinding
	imports := map[string]*sitter.Node{}
	exported := exportedNames(root, src)
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		t := n.Type()
		text := n.Content(src)
		switch t {
		case "function_definition":
			if params := n.ChildByFieldName("parameters"); params != nil {
				if hasMutableDefault(params.Content(src)) {
					out = append(out, pythonFinding("mutable-default", n, rel))
				}
				if explicitParams(params.Content(src)) > 7 {
					out = append(out, pythonFinding("args", n, rel))
				}
			}
			if nm := n.ChildByFieldName("name"); nm != nil && nm.Content(src) == "__init__" && pyInitReturnsValue(n) {
				out = append(out, pythonFinding("return-in-init", n, rel))
			}
			if body := n.ChildByFieldName("body"); body != nil && int(body.NamedChildCount()) > 50 {
				out = append(out, pythonFinding("long-function", n, rel))
			}
			if body := n.ChildByFieldName("body"); countReturnsBounded(body, map[string]bool{"function_definition": true, "lambda": true}) > 6 {
				out = append(out, pythonFinding("too-many-returns", n, rel))
			}
			if body := n.ChildByFieldName("body"); body != nil {
				if pyMaxDepthByType(body, pyControlTypes) > 4 {
					out = append(out, pythonFinding("deep-nesting", n, rel))
				}
				if pyMaxDepthByType(body, pyLoopTypes) >= 3 {
					out = append(out, pythonFinding("nested-loop", n, rel))
				}
				if pyComplexity(body) > 15 {
					out = append(out, pythonFinding("high-complexity", n, rel))
				}
			}
		case "if_statement", "while_statement":
			if cond := n.ChildByFieldName("condition"); cond != nil && pyCountBoolOps(cond) > 4 {
				out = append(out, pythonFinding("complex-condition", n, rel))
			}
		case "except_clause":
			if strings.HasPrefix(strings.TrimSpace(text), "except:") {
				out = append(out, pythonFinding("bare-except", n, rel))
			} else if broadExceptRE.MatchString(text) {
				out = append(out, pythonFinding("broad-except", n, rel))
			}
			if pyExceptOnlyPass(n) {
				out = append(out, pythonFinding("except-pass", n, rel))
			}
		case "conditional_expression":
			if pyHasDescendantType(n, "conditional_expression") {
				out = append(out, pythonFinding("nested-conditional", n, rel))
			}
		case "class_definition":
			if body := n.ChildByFieldName("body"); body != nil {
				funcs := 0
				for i := 0; i < int(body.NamedChildCount()); i++ {
					c := body.NamedChild(i)
					if c.Type() == "function_definition" {
						funcs++
					}
					if c.Type() == "expression_statement" {
						ct := strings.TrimSpace(c.Content(src))
						if eq := strings.Index(ct, "="); eq > 0 && ct[eq-1] != '=' && ct[eq-1] != '!' && ct[eq-1] != '<' && ct[eq-1] != '>' {
							v := strings.TrimSpace(ct[eq+1:])
							if strings.HasPrefix(v, "[") || strings.HasPrefix(v, "{") {
								out = append(out, pythonFinding("mutable-class-attr", c, rel))
							}
						}
					}
				}
				if funcs > 20 {
					out = append(out, pythonFinding("large-class", n, rel))
				}
			}
		case "assignment":
			if lambdaAssignRE.MatchString(text) {
				out = append(out, pythonFinding("lambda-assign", n, rel))
			}
			if builtinShadowRE.MatchString(text) {
				out = append(out, pythonFinding("shadow-builtin", n, rel))
			}
		case "string":
			if fStringEmptyRE.MatchString(text) && !strings.Contains(text, "{") {
				out = append(out, pythonFinding("fstring-empty", n, rel))
			}
		case "finally_clause":
			if controlInFinally(n, src) {
				out = append(out, pythonFinding("return-finally", n, rel))
			}
		case "dictionary":
			if duplicateLiteralKey(n, src) {
				out = append(out, pythonFinding("duplicate-dict", n, rel))
			}
		case "assert_statement":
			out = append(out, pythonFinding("assert", n, rel))
			if assertTupleRE.MatchString(text) {
				out = append(out, pythonFinding("assert-tuple", n, rel))
			}
		case "comparison_operator":
			if noneCompareRE.MatchString(text) {
				out = append(out, pythonFinding("none", n, rel))
			}
			if isLiteralRE.MatchString(text) {
				out = append(out, pythonFinding("is-literal", n, rel))
			}
			if emptyCompareRE.MatchString(text) {
				out = append(out, pythonFinding("compare-empty", n, rel))
			}
			if boolCompareRE.MatchString(text) {
				out = append(out, pythonFinding("compare-bool", n, rel))
			}
			if typeCompareRE.MatchString(text) {
				out = append(out, pythonFinding("type-eq", n, rel))
			}
			if lenZeroRE.MatchString(text) {
				out = append(out, pythonFinding("len-zero", n, rel))
			}
		case "import_from_statement":
			if strings.Contains(text, "*") {
				out = append(out, pythonFinding("star-import", n, rel))
			}
			if !isTypeCheckingImport(n, src) {
				for name := range importBindings(text) {
					imports[name] = n
				}
			}
		case "import_statement":
			if multiImportRE.MatchString(text) {
				out = append(out, pythonFinding("multi-import", n, rel))
			}
			if !isTypeCheckingImport(n, src) {
				for name := range importBindings(text) {
					imports[name] = n
				}
			}
		case "global_statement":
			out = append(out, pythonFinding("global", n, rel))
		case "raise_statement":
			if broadRaiseRE.MatchString(text) {
				out = append(out, pythonFinding("broad-raise", n, rel))
			}
		case "call":
			if directOpen(n, src) && !isWithResource(n) {
				out = append(out, pythonFinding("open", n, rel))
			}
			if fStringLog(n, src) {
				out = append(out, pythonFinding("f-log", n, rel))
			}
			if subprocessShellRE.MatchString(text) {
				out = append(out, pythonFinding("subprocess-shell", n, rel))
			}
			if bindAllRE.MatchString(text) {
				out = append(out, pythonFinding("bind-all", n, rel))
			}
			if mktempRE.MatchString(text) {
				out = append(out, pythonFinding("mktemp", n, rel))
			}
			if yamlLoadRE.MatchString(text) && !strings.Contains(text, "Loader") {
				out = append(out, pythonFinding("yaml-unsafe", n, rel))
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			stack = append(stack, n.Child(i))
		}
	}
	if filepath.Base(rel) != "__init__.py" {
		for name, n := range imports {
			if !exported[name] && !hasReference(root, src, name, n) {
				out = append(out, pythonFinding("unused-import", n, rel))
			}
		}
	}
	return dedupeQuality(out)
}

func pythonFinding(key string, n *sitter.Node, rel string) QualityFinding {
	r := pythonRules[key]
	return QualityFinding{Kind: r.kind, Rule: r.id, CWE: r.cwe, Severity: r.severity, Title: r.title, Description: r.description, File: rel, Line: int(n.StartPoint().Row) + 1}
}

func dedupeQuality(in []QualityFinding) []QualityFinding {
	seen := map[string]bool{}
	out := make([]QualityFinding, 0, len(in))
	for _, f := range in {
		key := f.Rule + "\x00" + f.File + "\x00" + string(rune(f.Line))
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func hasMutableDefault(s string) bool {
	for _, p := range splitParams(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "("), ")"))) {
		i := strings.Index(p, "=")
		if i < 0 {
			continue
		}
		value := strings.TrimSpace(p[i+1:])
		if strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{") {
			return true
		}
		for _, constructor := range []string{"set(", "list(", "dict(", "bytearray("} {
			if strings.HasPrefix(value, constructor) {
				return true
			}
		}
	}
	return false
}

func explicitParams(s string) int {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "("), ")"))
	if s == "" {
		return 0
	}
	n := 0
	for _, p := range splitParams(s) {
		name := strings.TrimSpace(strings.SplitN(strings.TrimSpace(p), "=", 2)[0])
		if i := strings.IndexAny(name, ":["); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}
		if name != "" && name != "/" && name != "self" && name != "cls" && !strings.HasPrefix(name, "*") {
			n++
		}
	}
	return n
}

func splitParams(s string) []string {
	var out []string
	start, depth := 0, 0
	var quote rune
	for i, r := range s {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

func controlInFinally(n *sitter.Node, src []byte) bool {
	stack := []*sitter.Node{n}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c != n && c.Type() == "function_definition" || c != n && c.Type() == "class_definition" {
			continue
		}
		if c != n && (c.Type() == "return_statement" || c.Type() == "break_statement") {
			return true
		}
		for i := 0; i < int(c.ChildCount()); i++ {
			stack = append(stack, c.Child(i))
		}
	}
	return false
}

func duplicateLiteralKey(n *sitter.Node, src []byte) bool {
	seen := map[string]bool{}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		pair := n.NamedChild(i)
		if pair.Type() != "pair" {
			continue
		}
		key := pair.ChildByFieldName("key")
		if key == nil {
			continue
		}
		canonical, ok := canonicalLiteralKey(strings.TrimSpace(key.Content(src)))
		if !ok {
			continue
		}
		if seen[canonical] {
			return true
		}
		seen[canonical] = true
	}
	return false
}

func canonicalLiteralKey(s string) (string, bool) {
	switch s {
	case "None":
		return "none", true
	case "True":
		return "number:1", true
	case "False":
		return "number:0", true
	}
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		// ponytail: common quoted literals only; extend with a Python literal evaluator when escape-equivalent keys matter.
		return "string:" + s[1:len(s)-1], true
	}
	if n, err := strconv.ParseFloat(strings.ReplaceAll(s, "_", ""), 64); err == nil {
		return "number:" + strconv.FormatFloat(n, 'g', -1, 64), true
	}
	return "", false
}

func directOpen(n *sitter.Node, src []byte) bool {
	fn := n.ChildByFieldName("function")
	return fn != nil && strings.TrimSpace(fn.Content(src)) == "open"
}

func isWithResource(n *sitter.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "with_item" {
			return true
		}
		if p.Type() == "with_statement" || p.Type() == "module" {
			return false
		}
	}
	return false
}

func fStringLog(n *sitter.Node, src []byte) bool {
	text := n.Content(src)
	if !fStringRE.MatchString(text) {
		return false
	}
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	name := strings.TrimSpace(fn.Content(src))
	for _, suffix := range []string{".debug", ".info", ".warning", ".error", ".critical", ".exception", ".log"} {
		if strings.HasSuffix(name, suffix) && (strings.HasPrefix(name, "logging.") || strings.HasPrefix(name, "logger.")) {
			return true
		}
	}
	return false
}

func importBindings(text string) map[string]bool {
	out := map[string]bool{}
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "from ") {
		if i := strings.Index(text, " import "); i >= 0 {
			for _, part := range strings.Split(text[i+8:], ",") {
				fields := strings.Fields(strings.TrimSpace(part))
				if len(fields) == 0 || fields[0] == "*" {
					continue
				}
				name := fields[0]
				if len(fields) >= 3 && fields[1] == "as" {
					name = fields[2]
				}
				out[name] = true
			}
		}
		return out
	}
	if strings.HasPrefix(text, "import ") {
		for _, part := range strings.Split(strings.TrimPrefix(text, "import "), ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) == 0 {
				continue
			}
			name := strings.Split(fields[0], ".")[0]
			if len(fields) >= 3 && fields[1] == "as" {
				name = fields[2]
			}
			out[name] = true
		}
	}
	return out
}

func isTypeCheckingImport(n *sitter.Node, src []byte) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "if_statement" {
			return strings.Contains(p.Content(src), "TYPE_CHECKING")
		}
		if p.Type() == "module" {
			break
		}
	}
	return false
}

func exportedNames(root *sitter.Node, src []byte) map[string]bool {
	out := map[string]bool{}
	text := string(src)
	re := regexp.MustCompile(`(?s)__all__\s*=\s*\[([^]]*)\]`)
	m := re.FindStringSubmatch(text)
	if len(m) == 2 {
		for _, q := range regexp.MustCompile(`['"]([^'"]+)['"]`).FindAllStringSubmatch(m[1], -1) {
			out[q[1]] = true
		}
	}
	return out
}

func hasReference(root *sitter.Node, src []byte, name string, decl *sitter.Node) bool {
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Type() == "import_statement" || n.Type() == "import_from_statement" {
			if n == decl {
				continue
			}
		}
		if n.Type() == "identifier" && n.Content(src) == name && !isBindingName(n) && !isShadowedByParameter(n, src, name) {
			return true
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			stack = append(stack, n.Child(i))
		}
	}
	return false
}

func isBindingName(n *sitter.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "parameters", "import_statement", "import_from_statement":
			return true
		case "assignment":
			return isDescendantOf(n, p.ChildByFieldName("left"))
		case "function_definition", "module":
			return false
		}
	}
	return false
}

func isDescendantOf(n, ancestor *sitter.Node) bool {
	for p := n; p != nil; p = p.Parent() {
		if p == ancestor {
			return true
		}
	}
	return false
}

func isShadowedByParameter(n *sitter.Node, src []byte, name string) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() != "function_definition" {
			continue
		}
		params := p.ChildByFieldName("parameters")
		if params != nil && parameterNames(params.Content(src))[name] {
			return true
		}
	}
	return false
}

func parameterNames(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range splitParams(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "("), ")"))) {
		name := strings.TrimSpace(strings.SplitN(strings.TrimSpace(p), "=", 2)[0])
		if i := strings.IndexAny(name, ":["); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}
		name = strings.TrimLeft(name, "*")
		if name != "" && name != "/" {
			out[name] = true
		}
	}
	return out
}
