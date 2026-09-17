//go:build cgo

package astwalk

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const maxCsharpFindingsPerFile = 40

// csharpRules is the metadata for the C# AST-only rules. Pattern-detectable C# rules live in the
// generated SAST language pack, and complexity is owned by the metrics path (cyclomatic
// quality-high-complexity), so this analyzer carries only the structural rules with no other
// producer: a regex cannot tell an empty catch from a commented one, a switch's default section
// from the word "default" elsewhere, or a type at namespace scope from one nested in a namespace.
var csharpRules = map[string]pythonRule{
	"empty-catch":         {"reliability", "csharp-ast-empty-catch", "CWE-390", "medium", "Empty catch block", "An empty catch block silently discards a failure. Handle the expected exception or preserve diagnostic context."},
	"missing-default":     {"reliability", "csharp-ast-missing-switch-default", "CWE-478", "medium", "switch without a default", "A switch with no default section silently ignores unhandled values; add a default (even one that throws)."},
	"throw-generic":       {"quality", "csharp-ast-throw-generic-exception", "CWE-397", "medium", "Generic exception thrown", "Throwing Exception, SystemException, or ApplicationException forces every caller to catch everything. Throw a specific exception type so callers can handle the failure they expect."},
	"rethrow-loses-trace": {"quality", "csharp-ast-rethrow-loses-stacktrace", "CWE-248", "medium", "Rethrow discards the stack trace", "Rethrowing the caught exception with `throw ex;` resets its stack trace to this line, hiding where the failure originated. Use `throw;` to preserve the original stack trace."},
	"unused-catch-var":    {"quality", "csharp-ast-unused-catch-variable", "", "low", "Unused catch variable", "The caught exception variable is never used in the catch block. Drop the binding (`catch (SomeException)`) or use it to log or wrap the failure."},
}

// maxCsharpUseScanNodes bounds the per-catch use scan so an adversarially large catch block cannot make
// variable-use resolution an uncapped walk.
const maxCsharpUseScanNodes = 8192

// csharpGenericExceptionTypes are the exception base types too broad to throw directly (SonarQube S112).
var csharpGenericExceptionTypes = map[string]bool{
	"Exception":            true,
	"SystemException":      true,
	"ApplicationException": true,
}

func csharpFinding(key string, n *sitter.Node, rel string) QualityFinding {
	r := csharpRules[key]
	return QualityFinding{Kind: r.kind, Rule: r.id, CWE: r.cwe, Severity: r.severity, Title: r.title, Description: r.description, File: rel, Line: int(n.StartPoint().Row) + 1}
}

// csharpFindings emits the C# AST rules: empty catch blocks and switch statements without a default
// section. It never suppresses; each finding is propose-only. (Complexity is reported by the metrics
// path as the cyclomatic quality-high-complexity finding, so it is not repeated here.)
func csharpFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	if root == nil {
		return nil
	}
	var out []QualityFinding
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch n.Type() {
		case "catch_clause":
			body := astChildByType(n, "block")
			switch {
			case body != nil && astBlockEmpty(body):
				out = append(out, csharpFinding("empty-catch", n, rel))
			case body != nil && csharpCatchVarUnused(n, body, src):
				out = append(out, csharpFinding("unused-catch-var", n, rel))
			}
		case "switch_statement":
			if body := astChildByType(n, "switch_body"); body != nil && !csharpSwitchHasDefault(body) {
				out = append(out, csharpFinding("missing-default", n, rel))
			}
		case "throw_statement":
			if oce := astChildByType(n, "object_creation_expression"); oce != nil && csharpThrowsGenericException(oce, src) {
				out = append(out, csharpFinding("throw-generic", n, rel))
			} else if id := astChildByType(n, "identifier"); id != nil && csharpRethrowsCaughtVar(n, id.Content(src), src) {
				out = append(out, csharpFinding("rethrow-loses-trace", n, rel))
			}
		}
		if len(out) >= maxCsharpFindingsPerFile {
			break
		}
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.Child(i))
		}
	}
	return dedupeQuality(out)
}

// csharpSwitchHasDefault reports whether a switch_body has a section that matches every remaining
// value, so the switch is not silently ignoring unhandled input.
func csharpSwitchHasDefault(body *sitter.Node) bool {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		sec := body.NamedChild(i)
		if sec.Type() == "switch_section" && csharpSectionIsExhaustive(sec) {
			return true
		}
	}
	return false
}

// csharpSectionIsExhaustive reports whether a switch_section matches every remaining value: a
// literal `default` label, a bare discard (`case _:`), or an unguarded `case var x:` (a var pattern
// matches all values). A `when` guard makes the section conditional, so it is NOT exhaustive.
func csharpSectionIsExhaustive(sec *sitter.Node) bool {
	var hasDefault, catchAll, hasWhen bool
	for i := 0; i < int(sec.ChildCount()); i++ {
		switch c := sec.Child(i); c.Type() {
		case "default":
			hasDefault = true
		case "discard":
			catchAll = true
		case "when_clause":
			hasWhen = true
		case "declaration_pattern":
			// `var x` (implicit_type) matches every value; a typed pattern (`int i`) does not.
			if csharpHasChildType(c, "implicit_type") {
				catchAll = true
			}
		}
	}
	if hasDefault {
		return true
	}
	return catchAll && !hasWhen
}

// csharpHasChildType reports whether n has a direct named child of the given type.
func csharpHasChildType(n *sitter.Node, t string) bool {
	return astChildByType(n, t) != nil
}

// csharpThrowsGenericException reports whether an object_creation_expression constructs one of the
// too-broad exception base types (Exception/SystemException/ApplicationException), matching SonarQube S112.
// The type may be qualified (System.Exception) or generic; only the final identifier segment is compared.
func csharpThrowsGenericException(oce *sitter.Node, src []byte) bool {
	typ := oce.ChildByFieldName("type")
	if typ == nil {
		return false
	}
	name := typ.Content(src)
	// Drop any generic argument list and namespace qualifier: System.Collections.Exception<T> -> Exception.
	if i := strings.IndexByte(name, '<'); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	return csharpGenericExceptionTypes[name]
}

// csharpCatchVarUnused reports whether a catch clause binds an exception variable that is never referenced
// in its (non-empty) block, so the binding is dead (SonarQube's unused-variable, CS0168). The empty-block
// case is left to empty-catch. The use scan is bounded and fails safe: if the block is larger than the node
// budget it is treated as using the variable, so a huge block never yields a false positive.
func csharpCatchVarUnused(catch, body *sitter.Node, src []byte) bool {
	cd := astChildByType(catch, "catch_declaration")
	if cd == nil {
		return false // `catch { }` with no binding: nothing to be unused
	}
	idn := astChildByType(cd, "identifier")
	if idn == nil {
		return false // `catch (SomeException)` with no name
	}
	name := idn.Content(src)
	return name != "" && !csharpIdentUsedIn(body, name, src)
}

// csharpIdentUsedIn reports whether an identifier with the given name appears anywhere under n. The walk is
// capped at maxCsharpUseScanNodes; on overflow it returns true (assume used) so it never over-reports.
func csharpIdentUsedIn(n *sitter.Node, name string, src []byte) bool {
	budget := maxCsharpUseScanNodes
	stack := []*sitter.Node{n}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if budget--; budget <= 0 {
			return true
		}
		if c.Type() == "identifier" && c.Content(src) == name {
			return true
		}
		for i := 0; i < int(c.ChildCount()); i++ {
			stack = append(stack, c.Child(i))
		}
	}
	return false
}

// csharpRethrowsCaughtVar reports whether `throw <name>;` rethrows the variable of the nearest enclosing
// catch clause, which resets the stack trace (SonarQube S3445 / CA2200). A bare `throw;` has no identifier
// and is not matched; `throw` of anything other than the caught variable, or outside a catch, is not
// flagged. The search stops at a method or lambda boundary so it never crosses into an unrelated scope.
func csharpRethrowsCaughtVar(n *sitter.Node, name string, src []byte) bool {
	if name == "" {
		return false
	}
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "catch_clause":
			cd := astChildByType(p, "catch_declaration")
			if cd == nil {
				return false
			}
			idn := astChildByType(cd, "identifier")
			return idn != nil && idn.Content(src) == name
		case "method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression", "anonymous_method_expression":
			return false
		}
	}
	return false
}
