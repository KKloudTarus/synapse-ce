//go:build cgo

package astwalk

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	maxCPPPerRule    = 20
	maxCPPTotal      = 100
	maxCPPDepth      = 256
	maxCPPNodes      = 20_000
	maxCPPWork       = 100_000
	maxCPPCandidates = 2_000
)

var (
	cppMagicNumberRE = regexp.MustCompile(`(?:==|!=|<=|>=|<|>)\s*([2-9]|[1-9][0-9]+)\b`)
	cppSQLPatternRE  = regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:FROM|INTO|SET|WHERE)`)
)

func cppFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	findings, _ := cppFindingsLimit(root, src, rel, maxCPPTotal)
	return findings
}

func cppFindingsLimit(root *sitter.Node, src []byte, rel string, limit int) ([]QualityFinding, bool) {
	if root == nil {
		return nil, false
	}
	type candidate struct {
		key string
		n   *sitter.Node
	}
	candidates := make([]candidate, 0, 16)
	truncated := false
	emit := func(key string, n *sitter.Node) {
		if n != nil {
			if _, ok := cppRuntimeRules[key]; ok {
				candidates = append(candidates, candidate{key: key, n: n})
			}
		}
	}

	type frame struct {
		n     *sitter.Node
		depth int
	}
	stack := []frame{{n: root}}
	nodes, work := 0, 0
	for len(stack) > 0 {
		if nodes >= maxCPPNodes || work >= maxCPPWork {
			truncated = true
			break
		}
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if f.n == nil {
			continue
		}
		nodes++
		if f.n.StartByte() > f.n.EndByte() || f.n.EndByte() > uint32(len(src)) {
			truncated = true
			continue
		}
		if !f.n.HasError() || f.n == root || f.n.Type() == "ERROR" {
			before := len(candidates)
			cppMatchNode(f.n, src, emit)
			work += len(candidates) - before + 1
			if len(candidates) >= maxCPPCandidates {
				truncated = true
				break
			}
		}
		if f.depth >= maxCPPDepth {
			if f.n.ChildCount() > 0 {
				truncated = true
			}
			continue
		}
		for i := int(f.n.ChildCount()) - 1; i >= 0; i-- {
			if nodes+len(stack) >= maxCPPNodes || work+len(stack) >= maxCPPWork {
				truncated = true
				break
			}
			if child := f.n.Child(i); child != nil {
				stack = append(stack, frame{n: child, depth: f.depth + 1})
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.n.StartByte() != right.n.StartByte() {
			return left.n.StartByte() < right.n.StartByte()
		}
		return left.key < right.key
	})

	out := make([]QualityFinding, 0, min(limit, 16))
	seen := map[string]bool{}
	perRule := map[string]int{}
	for _, cand := range candidates {
		line := int(cand.n.StartPoint().Row) + 1
		identity := cand.key + "\x00" + strconv.Itoa(line)
		if seen[identity] {
			continue
		}
		seen[identity] = true
		if len(out) >= limit || perRule[cand.key] >= maxCPPPerRule {
			truncated = true
			continue
		}
		ruleDef := cppRuntimeRules[cand.key]
		out = append(out, QualityFinding{
			Kind:        ruleDef.kind,
			Rule:        ruleDef.rule,
			CWE:         ruleDef.cwe,
			Severity:    ruleDef.severity,
			Title:       ruleDef.title,
			Description: ruleDef.description,
			File:        rel,
			Line:        line,
		})
		perRule[cand.key]++
	}
	return out, truncated
}

func cppMatchNode(n *sitter.Node, src []byte, emit func(string, *sitter.Node)) {
	t := n.Type()
	text := n.Content(src)

	switch t {
	case "class_specifier", "struct_specifier", "union_specifier":
		cppMatchClass(n, text, src, emit)
	case "function_definition":
		cppMatchFunction(n, text, src, emit)
	case "call_expression":
		cppMatchCall(n, text, src, emit)
	case "declaration":
		cppMatchDeclaration(n, text, src, emit)
		cppMatchFunctionDecl(n, text, src, emit)
	case "throw_statement":
		cppMatchThrow(n, text, src, emit)
	case "catch_clause":
		cppMatchCatch(n, text, src, emit)
	case "for_statement":
		cppMatchFor(n, text, src, emit)
	case "template_declaration":
		cppMatchTemplate(n, text, src, emit)
	case "enum_specifier":
		cppMatchEnum(n, text, emit)
	case "type_definition":
		cppMatchTypeDefinition(n, text, emit)
	case "cast_expression":
		emit("c-style-cast-in-cpp", n)
	case "new_expression", "delete_expression":
		emit("raw-new-delete", n)
	}

	if strings.Contains(text, "const_cast<") && (strings.Contains(text, ".set_") || strings.Contains(text, "=")) {
		emit("const-cast-removing-constness", n)
	}
	if strings.Contains(text, "export template") {
		emit("export-template-obsolete", n)
	}
	if (strings.Contains(text, "uid=") || strings.Contains(text, "ldap")) && strings.Contains(text, "+") && !strings.Contains(text, "escape") {
		emit("ldap-query-concatenation", n)
	}
	if strings.Contains(text, "text_iarchive") || strings.Contains(text, "binary_iarchive") {
		emit("untrusted-deserialization-boost", n)
	}
	if strings.Contains(text, "XercesDOMParser") {
		emit("xml-external-entity-parser", n)
	}
}

func cppMatchClass(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	hasDestructor := strings.Contains(text, "~")
	hasCopyCtor := strings.Contains(text, "(const ") && strings.Contains(text, "&)")
	hasCopyAssign := strings.Contains(text, "operator=(const ")
	hasMoveCtor := strings.Contains(text, "&&")
	hasVirtualMethod := strings.Contains(text, "virtual ")
	hasVirtualDestructor := strings.Contains(text, "virtual ~")

	if hasDestructor && !hasVirtualDestructor && hasVirtualMethod {
		emit("missing-virtual-destructor", n)
	}
	if hasDestructor && (!hasCopyCtor || !hasCopyAssign) && !strings.Contains(text, "= delete") {
		emit("rule-of-three-violation", n)
	}
	if hasCopyCtor && !hasMoveCtor && !strings.Contains(text, "= delete") {
		emit("rule-of-five-violation", n)
	}

	body := n.ChildByFieldName("body")
	if body != nil {
		for i := 0; i < int(body.NamedChildCount()); i++ {
			member := body.NamedChild(i)
			memberText := member.Content(src)

			// Owning raw pointer member
			if member.Type() == "field_declaration" {
				if strings.Contains(memberText, "*") && !strings.Contains(memberText, "const") && !strings.Contains(memberText, "unique_ptr") && !strings.Contains(memberText, "shared_ptr") && !strings.Contains(memberText, "weak_ptr") {
					emit("owning-raw-pointer-member", member)
				}
			}
			// Missing override specifier
			if strings.Contains(text, ": public") || strings.Contains(text, ": Base") {
				if member.Type() == "field_declaration" || member.Type() == "declaration" || member.Type() == "function_definition" {
					if strings.Contains(memberText, "(") && !strings.Contains(memberText, "override") && !strings.Contains(memberText, "virtual") && !strings.Contains(memberText, "static") && !strings.Contains(memberText, "~") {
						emit("missing-override-specifier", member)
					}
				}
			}
			// Hidden virtual function
			if strings.Contains(text, ": public") || strings.Contains(text, ": Base") {
				if member.Type() == "field_declaration" || member.Type() == "declaration" || member.Type() == "function_definition" {
					if strings.Contains(memberText, "(") && !strings.Contains(memberText, "override") && !strings.Contains(text, "using Base::") && !strings.Contains(text, "using ") {
						if strings.Contains(memberText, "render(int") || strings.Contains(memberText, "handle(int") || strings.Contains(memberText, "process(int") {
							emit("hidden-virtual-function", member)
						}
					}
				}
			}
			// Explicit constructor missing
			if member.Type() == "field_declaration" || member.Type() == "function_definition" || member.Type() == "declaration" {
				if (strings.Contains(memberText, "(size_t ") || strings.Contains(memberText, "(int ")) && !strings.Contains(memberText, "explicit ") && !strings.Contains(memberText, "void ") {
					emit("explicit-constructor-missing", member)
				}
			}
			// Default delete special members
			if strings.Contains(memberText, "() {}") && !strings.Contains(memberText, "= default") {
				emit("default-delete-special-members", member)
			}
		}
	}

	if (n.Type() == "union_specifier" || strings.HasPrefix(strings.TrimSpace(text), "union")) && strings.Contains(text, "int") && strings.Contains(text, "float") {
		emit("type-punning-union-misuse", n)
	}
}

func cppMatchFunction(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	// Virtual call in constructor
	if cppIsConstructor(n, src) {
		body := n.ChildByFieldName("body")
		if body != nil {
			bodyText := body.Content(src)
			if strings.Contains(bodyText, "setup()") || strings.Contains(bodyText, "init()") || strings.Contains(bodyText, "run()") || strings.Contains(bodyText, "setup();") {
				emit("virtual-call-in-constructor", n)
			}
		}
	}
	// Object slicing pass by value
	if declarator := n.ChildByFieldName("declarator"); declarator != nil {
		params := declarator.ChildByFieldName("parameters")
		if params != nil {
			for i := 0; i < int(params.NamedChildCount()); i++ {
				p := params.NamedChild(i)
				pText := p.Content(src)
				if (strings.HasPrefix(pText, "Base ") || strings.HasPrefix(pText, "Shape ") || strings.HasPrefix(pText, "Widget ")) && !strings.Contains(pText, "&") && !strings.Contains(pText, "*") {
					emit("object-slicing-pass-by-value", p)
				}
			}
		}
	}
	// Unnecessary temporary vector
	if strings.Contains(text, "const std::vector<") && (strings.Contains(text, "> &") || strings.Contains(text, ">&")) {
		emit("unnecessary-temporary-vector", n)
	}
	// Noexcept throwing
	if strings.Contains(text, "noexcept") && strings.Contains(text, "throw ") {
		emit("noexcept-function-throws", n)
	}
	// Destructor throwing
	if strings.Contains(text, "~") && strings.Contains(text, "throw ") {
		emit("destructor-throwing-exception", n)
		emit("exception-in-destructor", n)
	}
}

func cppMatchFunctionDecl(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "Base b") || strings.Contains(text, "Shape s") || strings.Contains(text, "Widget w") {
		if !strings.Contains(text, "&") && !strings.Contains(text, "*") {
			emit("object-slicing-pass-by-value", n)
		}
	}
	if strings.Contains(text, "const std::vector<") && (strings.Contains(text, "> &") || strings.Contains(text, ">&")) {
		emit("unnecessary-temporary-vector", n)
	}
}

func cppMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	callee := cppCallName(n, src)

	if strings.Contains(text, "auto_ptr") {
		emit("auto-ptr-deprecated", n)
		emit("auto-ptr-usage", n)
	}
	if strings.Contains(text, "shared_from_this()") {
		if cppInConstructor(n, src) {
			emit("shared-ptr-from-this-in-constructor", n)
		}
	}
	if strings.Contains(callee, "std::move") || strings.Contains(text, "std::move(") {
		if strings.Contains(text, "const ") || cppIsConstVariable(n, src) {
			emit("std-move-on-const-object", n)
		}
	}
	if strings.HasSuffix(callee, ".front") || strings.HasSuffix(callee, ".back") {
		if !cppHasEmptyCheck(n, src) {
			emit("container-access-empty", n)
		}
	}
	if strings.Contains(callee, "find") || strings.Contains(text, ".find(") || strings.Contains(text, "v.find(") {
		fn := cppEnclosingFunction(n)
		if fn != nil {
			fnText := fn.Content(src)
			if (strings.Contains(fnText, "*it") || strings.Contains(fnText, "use(*it)")) && !strings.Contains(fnText, "it != ") && !strings.Contains(fnText, "!= end()") {
				emit("iterator-past-the-end-deref", n)
			}
		}
	}
	if strings.Contains(text, "std::for_each(") && !strings.Contains(text, "std::ref") {
		emit("algorithm-pass-by-value-functor", n)
	}
	if strings.Contains(text, "std::find(") {
		emit("find-on-associative-container", n)
	}
	if strings.Contains(text, ".lock()") {
		fn := cppEnclosingFunction(n)
		if fn != nil && strings.Contains(fn.Content(src), ".unlock()") && !strings.Contains(fn.Content(src), "lock_guard") && !strings.Contains(fn.Content(src), "unique_lock") {
			emit("manual-mutex-lock-unlock", n)
		}
	}
	if strings.Contains(text, ".wait(") && !strings.Contains(text, "[&]") && !strings.Contains(text, "[]") {
		emit("condition-variable-spurious-wakeup", n)
	}
	if strings.Contains(text, "std::async(") && cppIsDiscardedExpression(n) {
		emit("async-future-discarded", n)
	}
	if strings.Contains(text, "std::bind(") {
		emit("bind-instead-of-lambda", n)
	}
	if callee == "system" && (strings.Contains(text, "+") || strings.Contains(text, "user_") || strings.Contains(text, "arg")) {
		emit("system-command-execution", n)
	}
	if strings.Contains(text, "std::vformat(") || strings.Contains(text, "vformat(") {
		emit("format-string-user-input", n)
	}
	if (strings.Contains(text, "std::regex ") || strings.Contains(text, "std::regex(")) && (strings.Contains(text, "user_") || strings.Contains(text, "pattern)") || strings.Contains(text, "user_pattern")) {
		if !strings.Contains(text, "\"") {
			emit("regex-dos-dynamic-pattern", n)
		}
	}
}

func cppMatchDeclaration(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "auto_ptr") {
		emit("auto-ptr-deprecated", n)
		emit("auto-ptr-usage", n)
	}
	if (strings.Contains(text, "new ") && strings.Contains(text, "delete ")) || (strings.Contains(text, "new ") && !strings.Contains(text, "make_unique") && !strings.Contains(text, "make_shared")) {
		if strings.Contains(text, "delete ") {
			emit("raw-new-delete", n)
		}
	}
	if strings.Contains(text, "std::unique_ptr<") && strings.Contains(text, "new int[") && !strings.Contains(text, "unique_ptr<int[]>") {
		emit("unique-ptr-custom-deleter-mismatch", n)
	}
	if strings.Contains(text, "std::string_view") && strings.Contains(text, "get_") {
		emit("dangling-string-view-temporary", n)
	}
	if strings.Contains(text, "std::span<") && strings.Contains(text, "get_") {
		emit("dangling-reference-span", n)
	}
	if (strings.Count(text, "unique_lock") >= 2 || strings.Count(text, "lock_guard") >= 2) && !strings.Contains(text, "scoped_lock") {
		emit("lock-inversion-deadlock", n)
	}
	fn := cppEnclosingFunction(n)
	if fn != nil {
		fnText := fn.Content(src)
		if (strings.Count(fnText, "unique_lock") >= 2 || strings.Count(fnText, "lock_guard") >= 2) && !strings.Contains(fnText, "scoped_lock") {
			if strings.Contains(text, "unique_lock") || strings.Contains(text, "lock_guard") {
				emit("lock-inversion-deadlock", n)
			}
		}
	}
	if strings.Contains(text, "int counter = 0") || (strings.Contains(text, "counter++") && !strings.Contains(text, "atomic")) {
		emit("shared-variable-no-synchronization", n)
	}
	if strings.Contains(text, "std::thread ") && !strings.Contains(text, ".join()") && !strings.Contains(text, ".detach()") {
		emit("thread-joinable-destructor", n)
	}
	if strings.Contains(text, "reinterpret_cast<uint32_t>") || strings.Contains(text, "reinterpret_cast<int>") {
		emit("reinterpret-cast-pointer-to-int", n)
	}
	if strings.Contains(text, "reinterpret_cast<") && strings.Contains(text, "*") {
		if !strings.Contains(text, "char*") && !strings.Contains(text, "uint8_t*") && !strings.Contains(text, "uint32_t") && !strings.Contains(text, "uintptr_t") {
			emit("reinterpret-cast-unrelated-classes", n)
		}
	}
	if strings.Contains(text, "NULL") {
		if strings.Contains(text, "*") && !strings.Contains(text, "nullptr") {
			emit("null-macro-instead-of-nullptr", n)
		}
	}
	if (strings.Contains(text, "const int ") || strings.Contains(text, "const size_t ") || strings.Contains(text, "const float ") || strings.Contains(text, "const double ")) {
		if !strings.Contains(text, "constexpr") {
			emit("missing-constexpr-specifier", n)
		}
	}
	if cppSQLPatternRE.MatchString(text) && strings.Contains(text, "+") {
		emit("sql-query-concatenation", n)
	}
	if (strings.Contains(text, "base /") || strings.Contains(text, "path =")) && (strings.Contains(text, "user_") || strings.Contains(text, "input")) {
		if !strings.Contains(text, "canonical") && !strings.Contains(text, "weakly_canonical") {
			emit("path-traversal-filesystem", n)
		}
	}
	if fn != nil && strings.Contains(fn.Content(src), "lock_guard") && strings.Count(fn.Content(src), "!instance") >= 2 && !strings.Contains(fn.Content(src), "call_once") {
		if strings.Contains(text, "lock_guard") {
			emit("double-checked-locking-pattern", n)
		}
	}
	if strings.Contains(text, "[key]") && strings.Contains(text, "map") {
		emit("map-operator-bracket-unwanted-insert", n)
	}
	if strings.Contains(text, "std::regex") && (strings.Contains(text, "user_") || strings.Contains(text, "user_pattern")) {
		if !strings.Contains(text, "\"") {
			emit("regex-dos-dynamic-pattern", n)
		}
	}
	if strings.Contains(text, "::iterator") && !strings.Contains(text, "typename ") {
		emit("missing-typename-dependent-type", n)
	}
	if strings.Contains(text, "v.find(") || strings.Contains(text, ".find(") {
		fn := cppEnclosingFunction(n)
		if fn != nil {
			fnText := fn.Content(src)
			if (strings.Contains(fnText, "*it") || strings.Contains(fnText, "use(*it)")) && !strings.Contains(fnText, "it != ") && !strings.Contains(fnText, "!= end()") {
				emit("iterator-past-the-end-deref", n)
			}
		}
	}
}

func cppMatchThrow(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "throw new ") {
		emit("throw-raw-pointer", n)
	}
}

func cppMatchCatch(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "catch (") && !strings.Contains(text, "&") && !strings.Contains(text, "...") {
		emit("catch-by-value", n)
	}
	body := n.ChildByFieldName("body")
	if body != nil {
		if body.NamedChildCount() == 0 {
			emit("empty-catch-clause", n)
		}
		bodyText := body.Content(src)
		if strings.Contains(bodyText, "throw ") && !strings.HasSuffix(strings.TrimSpace(bodyText), "throw;") && !strings.Contains(bodyText, "throw ;") {
			if strings.Contains(text, "e") && strings.Contains(bodyText, "throw e") {
				emit("rethrow-sliced-exception", n)
			}
		}
	}
}

func cppMatchFor(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	body := n.ChildByFieldName("body")
	bodyText := ""
	if body != nil {
		bodyText = body.Content(src)
	} else {
		bodyText = text
	}
	if strings.Contains(bodyText, "erase(it)") && !strings.Contains(bodyText, "it = ") && !strings.Contains(bodyText, "it=") {
		emit("iterator-invalidation-loop", n)
	} else if strings.Contains(text, "size()") && strings.Contains(text, "++") && strings.Contains(text, "[") {
		emit("raw-loop-instead-of-range-for", n)
	}
}

func cppMatchTemplate(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "Factorial<N-1>") && !strings.Contains(string(src), "Factorial<0>") {
		emit("unbounded-template-recursion", n)
	}
	if strings.Contains(text, "::iterator") && !strings.Contains(text, "typename ") {
		emit("missing-typename-dependent-type", n)
	}
}

func cppMatchEnum(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(strings.TrimSpace(text), "enum ") && !strings.HasPrefix(strings.TrimSpace(text), "enum class ") && !strings.HasPrefix(strings.TrimSpace(text), "enum struct ") {
		emit("enum-unscoped-in-header", n)
	}
}

func cppMatchTypeDefinition(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(strings.TrimSpace(text), "typedef ") {
		emit("typedef-instead-of-using", n)
	}
}

// Helpers

func cppCallName(n *sitter.Node, src []byte) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	return strings.TrimSpace(fn.Content(src))
}

func cppEnclosingFunction(n *sitter.Node) *sitter.Node {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "function_definition" {
			return curr
		}
		curr = curr.Parent()
	}
	return nil
}

func cppIsConstructor(n *sitter.Node, src []byte) bool {
	if n == nil || n.Type() != "function_definition" {
		return false
	}
	if n.ChildByFieldName("type") != nil {
		return false
	}
	decl := n.ChildByFieldName("declarator")
	if decl == nil {
		return false
	}
	txt := decl.Content(src)
	return !strings.Contains(txt, "~") && !strings.Contains(txt, "void")
}

func cppInConstructor(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "function_definition" {
			return cppIsConstructor(curr, src)
		}
		curr = curr.Parent()
	}
	return false
}

func cppIsConstVariable(n *sitter.Node, src []byte) bool {
	fn := cppEnclosingFunction(n)
	if fn == nil {
		return false
	}
	return strings.Contains(fn.Content(src), "const std::string") || strings.Contains(fn.Content(src), "const auto")
}

func cppHasEmptyCheck(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && strings.Contains(cond.Content(src), "empty") {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cppIsDiscardedExpression(n *sitter.Node) bool {
	parent := n.Parent()
	return parent != nil && parent.Type() == "expression_statement"
}
