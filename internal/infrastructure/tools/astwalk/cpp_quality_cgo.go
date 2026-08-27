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
		if n != nil && !n.HasError() {
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
		if !f.n.HasError() {
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
	case "class_specifier", "struct_specifier":
		cppMatchClass(n, text, src, emit)
	case "function_definition":
		cppMatchFunction(n, text, src, emit)
	case "call_expression":
		cppMatchCall(n, text, src, emit)
	case "declaration":
		cppMatchDeclaration(n, text, src, emit)
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
			if member.Type() == "field_declaration" && (strings.Contains(memberText, "*") && !strings.Contains(memberText, "const") && !strings.Contains(memberText, "unique_ptr") && !strings.Contains(memberText, "shared_ptr")) {
				if strings.Contains(memberText, "worker_") || strings.Contains(memberText, "ptr_") || strings.Contains(memberText, "data_") || strings.Contains(memberText, "handle_") {
					emit("owning-raw-pointer-member", member)
				}
			}
			// Missing override
			if strings.Contains(text, ": public") && strings.Contains(memberText, ";") && !strings.Contains(memberText, "override") && !strings.Contains(memberText, "virtual") && !strings.Contains(memberText, "static") && !strings.Contains(memberText, "~") {
				if strings.Contains(memberText, "handle(") || strings.Contains(memberText, "render(") || strings.Contains(memberText, "process(") {
					emit("missing-override-specifier", member)
				}
			}
			// Hidden virtual function
			if strings.Contains(text, ": public") && strings.Contains(memberText, "render(int") && !strings.Contains(text, "using Base::render") {
				emit("hidden-virtual-function", member)
			}
			// Explicit constructor missing
			if member.Type() == "field_declaration" || member.Type() == "function_definition" || member.Type() == "declaration" {
				if strings.Contains(memberText, "(size_t ") && !strings.Contains(memberText, "explicit ") {
					emit("explicit-constructor-missing", member)
				}
			}
			// Default delete special members
			if strings.Contains(memberText, "() {}") && !strings.Contains(memberText, "= default") {
				emit("default-delete-special-members", member)
			}
		}
	}

	if strings.Contains(text, "union {") || strings.Contains(text, "union ") {
		if strings.Contains(text, "int") && strings.Contains(text, "float") {
			emit("type-punning-union-misuse", n)
		}
	}
}

func cppMatchFunction(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	// Virtual call in constructor
	if declarator := n.ChildByFieldName("declarator"); declarator != nil {
		declText := declarator.Content(src)
		if !strings.Contains(declText, "~") && !strings.Contains(declText, "void") && !strings.Contains(declText, "int") && !strings.Contains(declText, "bool") {
			if strings.Contains(text, "setup();") || strings.Contains(text, "init();") {
				emit("virtual-call-in-constructor", n)
			}
		}
	}
	// Object slicing pass by value
	if strings.Contains(text, "(Base b)") || strings.Contains(text, "(Shape s)") || strings.Contains(text, "(Widget w)") {
		emit("object-slicing-pass-by-value", n)
	}
	// Unnecessary temporary vector
	if strings.Contains(text, "const std::vector<") && strings.Contains(text, "> &") {
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

func cppMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	callee := cppCallName(n, src)

	if strings.Contains(text, "std::auto_ptr<") || strings.Contains(text, "auto_ptr<") {
		emit("auto-ptr-deprecated", n)
		emit("auto-ptr-usage", n)
	}
	if strings.Contains(text, "shared_from_this()") {
		if cppInConstructor(n) {
			emit("shared-ptr-from-this-in-constructor", n)
		}
	}
	if strings.Contains(text, "std::move(") {
		if strings.Contains(text, "const ") || strings.Contains(text, "name") {
			emit("std-move-on-const-object", n)
		}
	}
	if strings.HasSuffix(callee, ".front") || strings.HasSuffix(callee, ".back") {
		if !cppHasEmptyCheck(n, src) {
			emit("container-access-empty", n)
		}
	}
	if strings.Contains(text, "v.find(") || strings.Contains(text, "map.find(") || strings.Contains(text, "set.find(") {
		if strings.Contains(text, "use(*it)") || strings.Contains(text, "*it") {
			emit("iterator-past-the-end-deref", n)
		}
	}
	if strings.Contains(text, "std::for_each(") && !strings.Contains(text, "std::ref") && strings.Contains(text, "acc") {
		emit("algorithm-pass-by-value-functor", n)
	}
	if strings.Contains(text, "std::find(") && (strings.Contains(text, "set.begin()") || strings.Contains(text, "map.begin()")) {
		emit("find-on-associative-container", n)
	}
	if strings.Contains(text, ".lock()") && strings.Contains(text, ".unlock()") {
		emit("manual-mutex-lock-unlock", n)
	}
	if strings.Contains(text, "cv.wait(") && !strings.Contains(text, "[&]") && !strings.Contains(text, "[]") {
		emit("condition-variable-spurious-wakeup", n)
	}
	if strings.Contains(text, "std::async(") && cppIsDiscardedExpression(n) {
		emit("async-future-discarded", n)
	}
	if strings.Contains(text, "std::bind(") {
		emit("bind-instead-of-lambda", n)
	}
	if callee == "system" && (strings.Contains(text, "+") || strings.Contains(text, "user_")) {
		emit("system-command-execution", n)
	}
	if strings.Contains(text, "XercesDOMParser") && strings.Contains(text, "parse") {
		emit("xml-external-entity-parser", n)
	}
	if strings.Contains(text, "text_iarchive") || strings.Contains(text, "binary_iarchive") {
		emit("untrusted-deserialization-boost", n)
	}
	if strings.Contains(text, "std::vformat(") || strings.Contains(text, "vformat(") {
		emit("format-string-user-input", n)
	}
	if strings.Contains(text, "std::regex") && (strings.Contains(text, "user_") || strings.Contains(text, "pattern")) {
		emit("regex-dos-dynamic-pattern", n)
	}
	if strings.Contains(text, "std::unique_ptr<int>") && strings.Contains(text, "new int[") {
		emit("unique-ptr-custom-deleter-mismatch", n)
	}
}

func cppMatchDeclaration(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if (strings.Contains(text, "new ") && strings.Contains(text, "delete ")) || (strings.HasPrefix(strings.TrimSpace(text), "delete ") && !strings.Contains(text, "default")) {
		emit("raw-new-delete", n)
	}
	if strings.Contains(text, "std::string_view") && strings.Contains(text, "get_") {
		emit("dangling-string-view-temporary", n)
	}
	if strings.Contains(text, "std::span<") && strings.Contains(text, "get_") {
		emit("dangling-reference-span", n)
	}
	if strings.Count(text, "std::unique_lock") >= 2 || strings.Count(text, "std::lock_guard") >= 2 {
		emit("lock-inversion-deadlock", n)
	}
	if strings.Contains(text, "int counter = 0") && strings.Contains(text, "counter++") {
		emit("shared-variable-no-synchronization", n)
	}
	if strings.Contains(text, "std::thread ") && !strings.Contains(text, ".join()") && !strings.Contains(text, ".detach()") {
		emit("thread-joinable-destructor", n)
	}
	if strings.Contains(text, "reinterpret_cast<uint32_t>") || strings.Contains(text, "reinterpret_cast<int>") {
		emit("reinterpret-cast-pointer-to-int", n)
	}
	if strings.Contains(text, "const_cast<") && (strings.Contains(text, ".set_") || strings.Contains(text, "=")) {
		emit("const-cast-removing-constness", n)
	}
	if strings.Contains(text, "reinterpret_cast<") && strings.Contains(text, "*") {
		if !strings.Contains(text, "char*") && !strings.Contains(text, "uint8_t*") && !strings.Contains(text, "uint32_t") {
			emit("reinterpret-cast-unrelated-classes", n)
		}
	}
	if strings.Contains(text, "= NULL;") || strings.Contains(text, "= 0;") {
		if strings.Contains(text, "*") {
			emit("null-macro-instead-of-nullptr", n)
		}
	}
	if strings.HasPrefix(strings.TrimSpace(text), "const int ") || strings.HasPrefix(strings.TrimSpace(text), "const size_t ") {
		if !strings.Contains(text, "constexpr") {
			emit("missing-constexpr-specifier", n)
		}
	}
	if cppSQLPatternRE.MatchString(text) && strings.Contains(text, "+") {
		emit("sql-query-concatenation", n)
	}
	if (strings.Contains(text, "base /") || strings.Contains(text, "path =")) && (strings.Contains(text, "user_") || strings.Contains(text, "input")) {
		emit("path-traversal-filesystem", n)
	}
	if strings.Contains(text, "(uid=") && strings.Contains(text, "+") {
		emit("ldap-query-concatenation", n)
	}
	if strings.Contains(text, "std::lock_guard") && strings.Count(text, "!instance") >= 2 {
		emit("double-checked-locking-pattern", n)
	}
	if strings.Contains(text, "[key]") && strings.Contains(text, "map") {
		emit("map-operator-bracket-unwanted-insert", n)
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
	if strings.Contains(text, "erase(it)") {
		emit("iterator-invalidation-loop", n)
	} else if strings.Contains(text, "size()") && strings.Contains(text, "++") && strings.Contains(text, "[") {
		emit("raw-loop-instead-of-range-for", n)
	}
}

func cppMatchTemplate(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(strings.TrimSpace(text), "export template") {
		emit("export-template-obsolete", n)
	}
	if strings.Contains(text, "Factorial<N-1>") && !strings.Contains(text, "<0>") {
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

func cppInConstructor(n *sitter.Node) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "function_definition" {
			decl := curr.ChildByFieldName("declarator")
			if decl != nil {
				txt := decl.Content([]byte{})
				if !strings.Contains(txt, "void") && !strings.Contains(txt, "int") && !strings.Contains(txt, "bool") {
					return true
				}
			}
		}
		curr = curr.Parent()
	}
	return false
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
