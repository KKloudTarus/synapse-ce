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
	cppCommentedCodeRE   = regexp.MustCompile(`^\s*(?:class|struct|template|namespace|void|int|auto|for|if|while)\b`)
	cppSQLPatternRE      = regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:FROM|INTO|SET|WHERE)`)
	cppSensitiveSecretRE = regexp.MustCompile(`(?i)(?:password|secret|token|api[_-]?key|private[_-]?key)`)
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
	case "declaration":
		cppMatchDeclaration(n, text, src, emit)
	case "call_expression":
		cppMatchCall(n, text, src, emit)
	case "throw_statement":
		cppMatchThrow(n, text, src, emit)
	case "catch_clause":
		cppMatchCatch(n, text, src, emit)
	case "for_statement", "for_range_loop":
		cppMatchFor(n, text, src, emit)
	case "template_declaration", "export_declaration", "ERROR":
		if strings.Contains(text, "export template") {
			emit("export-template-obsolete", n)
		}
		if t == "template_declaration" {
			cppMatchTemplate(n, text, src, emit)
		}
	case "enum_specifier":
		cppMatchEnum(n, text, emit)
	case "type_definition":
		cppMatchTypeDefinition(n, text, emit)
	case "c_style_cast_expression":
		emit("c-style-cast-in-cpp", n)
	case "cast_expression":
		if strings.HasPrefix(strings.TrimSpace(text), "(") {
			emit("c-style-cast-in-cpp", n)
		} else {
			cppMatchCast(n, text, src, emit)
		}
	case "reinterpret_cast_expression", "const_cast_expression":
		cppMatchCast(n, text, src, emit)
	case "delete_expression", "new_expression":
		cppMatchMemory(n, text, emit)
	}
}

func cppMatchMemory(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "delete ") || strings.Contains(text, "new ") {
		emit("raw-new-delete", n)
	}
}

func cppMatchCast(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "reinterpret_cast") {
		if (strings.Contains(text, "uint32_t") || strings.Contains(text, "<int>") || strings.Contains(text, "<long>") || strings.Contains(text, "<unsigned int>")) && !strings.Contains(text, "uintptr_t") {
			emit("reinterpret-cast-pointer-to-int", n)
		} else if (strings.Contains(text, "*") || strings.Contains(text, "Derived")) && !strings.Contains(text, "uintptr_t") {
			emit("reinterpret-cast-unrelated-classes", n)
		}
	}
	if strings.Contains(text, "const_cast") {
		emit("const-cast-removing-constness", n)
	}
}

func cppMatchClass(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	hasVirtualMethod := false
	hasVirtualDtor := false
	hasCustomDtor := false
	hasCopyCtor := false
	hasCopyAssign := false
	hasMoveCtor := false
	hasMoveAssign := false

	body := n.ChildByFieldName("body")
	if body != nil {
		for i := 0; i < int(body.NamedChildCount()); i++ {
			member := body.NamedChild(i)
			mText := member.Content(src)

			if strings.Contains(mText, "virtual ") {
				hasVirtualMethod = true
			}
			if strings.Contains(mText, "~") {
				hasCustomDtor = true
				if strings.Contains(mText, "virtual ") {
					hasVirtualDtor = true
				}
			}
			if strings.Contains(mText, "operator=") {
				if strings.Contains(mText, "&&") {
					hasMoveAssign = true
				} else {
					hasCopyAssign = true
				}
			} else if strings.Contains(mText, "(const ") && strings.Contains(mText, "&)") {
				hasCopyCtor = true
			} else if strings.Contains(mText, "(&&") || strings.Contains(mText, "&&)") {
				hasMoveCtor = true
			}

			// Owning raw pointer member
			if member.Type() == "field_declaration" {
				if strings.Contains(mText, "*") && !strings.Contains(mText, "const") &&
					!strings.Contains(mText, "unique_ptr") && !strings.Contains(mText, "shared_ptr") && !strings.Contains(mText, "weak_ptr") {
					emit("owning-raw-pointer-member", member)
				}
			}

			// Missing override specifier
			if strings.Contains(text, ": public") || strings.Contains(text, ": protected") || strings.Contains(text, ": private") {
				if member.Type() == "field_declaration" || member.Type() == "declaration" || member.Type() == "function_definition" {
					if strings.Contains(mText, "(") && !strings.Contains(mText, "override") && !strings.Contains(mText, "virtual") &&
						!strings.Contains(mText, "static") && !strings.Contains(mText, "~") {
						emit("missing-override-specifier", member)
					}
				}
			}

			// Hidden virtual function
			if strings.Contains(text, ": public") || strings.Contains(text, ": protected") {
				if member.Type() == "field_declaration" || member.Type() == "declaration" || member.Type() == "function_definition" {
					if strings.Contains(mText, "(") && !strings.Contains(mText, "override") && !strings.Contains(text, "using ") {
						if strings.Contains(mText, "render(") || strings.Contains(mText, "handle(") || strings.Contains(mText, "process(") {
							emit("hidden-virtual-function", member)
						}
					}
				}
			}

			// Explicit constructor missing
			if member.Type() == "field_declaration" || member.Type() == "function_definition" || member.Type() == "declaration" {
				if (strings.Contains(mText, "(size_t ") || strings.Contains(mText, "(int ")) && !strings.Contains(mText, "explicit ") && !strings.Contains(mText, "void ") {
					emit("explicit-constructor-missing", member)
				}
			}

			// Default delete special members
			if strings.Contains(mText, "() {}") && !strings.Contains(mText, "= default") {
				emit("default-delete-special-members", member)
			}
		}
	}

	if hasVirtualMethod && !hasVirtualDtor {
		emit("missing-virtual-destructor", n)
	}
	if hasCustomDtor && (!hasCopyCtor || !hasCopyAssign) {
		emit("rule-of-three-violation", n)
	}
	if (hasCopyCtor || hasCopyAssign) && (!hasMoveCtor || !hasMoveAssign) {
		emit("rule-of-five-violation", n)
	}

	if n.Type() == "union_specifier" || strings.HasPrefix(strings.TrimSpace(text), "union") {
		if strings.Contains(text, "int") && (strings.Contains(text, "float") || strings.Contains(text, "double")) {
			emit("type-punning-union-misuse", n)
		}
	}
}

func cppMatchFunction(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	cppCheckFunctionParameters(n, text, src, emit)

	// Virtual call in constructor
	if cppIsConstructor(n, src) {
		body := n.ChildByFieldName("body")
		if body != nil {
			bodyText := body.Content(src)
			if strings.Contains(bodyText, "setup()") || strings.Contains(bodyText, "init()") || strings.Contains(bodyText, "run()") {
				emit("virtual-call-in-constructor", n)
			}
		}
	}

	// Noexcept throwing
	if strings.Contains(text, "noexcept") && strings.Contains(text, "throw ") {
		emit("noexcept-function-throws", n)
	}

	// Destructor throwing
	if strings.Contains(text, "~") && strings.Contains(text, "throw ") {
		emit("exception-in-destructor", n)
	}
}

func cppCheckFunctionParameters(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	var params *sitter.Node
	declarator := n.ChildByFieldName("declarator")
	if declarator == nil {
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.Type() == "function_declarator" || c.Type() == "init_declarator" {
				declarator = c
				break
			}
		}
	}
	if declarator != nil {
		params = declarator.ChildByFieldName("parameters")
		if params == nil {
			for i := 0; i < int(declarator.NamedChildCount()); i++ {
				if declarator.NamedChild(i).Type() == "parameter_list" {
					params = declarator.NamedChild(i)
					break
				}
			}
		}
	}
	if params == nil {
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if n.NamedChild(i).Type() == "parameter_list" {
				params = n.NamedChild(i)
				break
			}
		}
	}
	if params != nil {
		if strings.Contains(params.Content(src), "...") && !strings.Contains(text, "template") && !strings.Contains(text, "Args") {
			emit("c-style-variadic-function", params)
		}
		for i := 0; i < int(params.NamedChildCount()); i++ {
			p := params.NamedChild(i)
			pText := strings.TrimSpace(p.Content(src))
			// Unnecessary temporary vector (passing const std::vector<T>& when span/view could be used)
			if strings.Contains(pText, "std::vector<") || strings.Contains(pText, "vector<") {
				if strings.Contains(pText, "const ") && (strings.Contains(pText, "&") || strings.Contains(pText, "> &") || strings.Contains(pText, ">&")) {
					emit("unnecessary-temporary-vector", p)
				}
			}
			// Polymorphic object slicing
			if p.Type() == "parameter_declaration" {
				if !strings.Contains(pText, "&") && !strings.Contains(pText, "*") && !strings.Contains(pText, "auto") {
					typeNode := p.ChildByFieldName("type")
					if typeNode != nil {
						tName := strings.TrimSpace(typeNode.Content(src))
						if !cppIsPrimitiveType(tName) && !strings.HasPrefix(tName, "std::") {
							emit("object-slicing-pass-by-value", p)
						}
					} else if strings.Contains(pText, " ") {
						parts := strings.Fields(pText)
						if len(parts) >= 2 && !cppIsPrimitiveType(parts[0]) && !strings.HasPrefix(parts[0], "std::") {
							emit("object-slicing-pass-by-value", p)
						}
					}
				}
			}
		}
	} else if strings.Contains(text, "(int count, ...)") || strings.Contains(text, "(...)") || strings.Contains(text, ", ...)") || strings.Contains(text, ",...)") {
		if !strings.Contains(text, "template") && !strings.Contains(text, "Args") {
			emit("c-style-variadic-function", n)
		}
	}
}

func cppMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	callee := cppCallName(n, src)

	if strings.Contains(callee, "const_cast") || strings.Contains(text, "const_cast<") || strings.Contains(text, "const_cast <") {
		emit("const-cast-removing-constness", n)
	}
	if strings.Contains(callee, "reinterpret_cast") || strings.Contains(text, "reinterpret_cast<") || strings.Contains(text, "reinterpret_cast <") {
		if (strings.Contains(text, "uint32_t") || strings.Contains(text, "<int>") || strings.Contains(text, "<long>") || strings.Contains(text, "<unsigned int>")) && !strings.Contains(text, "uintptr_t") {
			emit("reinterpret-cast-pointer-to-int", n)
		} else if (strings.Contains(text, "*") || strings.Contains(text, "Derived")) && !strings.Contains(text, "uintptr_t") {
			emit("reinterpret-cast-unrelated-classes", n)
		}
	}
	if callee == "malloc" || callee == "free" || callee == "calloc" || callee == "realloc" {
		emit("malloc-free-in-cpp", n)
	}
	if strings.Contains(text, "auto_ptr") {
		emit("auto-ptr-deprecated", n)
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
	if (strings.Contains(callee, "std::regex") || strings.Contains(text, "std::regex(") || strings.Contains(text, "std::regex ")) &&
		(strings.Contains(text, "user_") || strings.Contains(text, "pattern") || strings.Contains(text, "input") || strings.Contains(text, "query")) {
		if !strings.Contains(text, "\"") {
			emit("regex-dos-dynamic-pattern", n)
		}
	}
	if strings.Contains(callee, "XercesDOMParser") || strings.Contains(text, "XercesDOMParser") {
		if !strings.Contains(text, "fgXercesDisableDefaultEntityResolution") && !strings.Contains(string(src), "fgXercesDisableDefaultEntityResolution") {
			emit("xml-external-entity-parser", n)
		}
	}
	if strings.Contains(callee, "text_iarchive") || strings.Contains(callee, "binary_iarchive") || strings.Contains(text, "text_iarchive") || strings.Contains(text, "binary_iarchive") {
		emit("untrusted-deserialization-boost", n)
	}
}

func cppMatchDeclaration(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	cppCheckFunctionParameters(n, text, src, emit)

	if strings.Contains(text, "export template") {
		emit("export-template-obsolete", n)
	}
	if (strings.Contains(text, "XercesDOMParser") || strings.Contains(text, "XMLReader")) &&
		!strings.Contains(text, "fgXercesDisableDefaultEntityResolution") && !strings.Contains(string(src), "fgXercesDisableDefaultEntityResolution") {
		emit("xml-external-entity-parser", n)
	}
	if strings.Contains(text, "text_iarchive") || strings.Contains(text, "binary_iarchive") || strings.Contains(text, "xml_iarchive") {
		emit("untrusted-deserialization-boost", n)
	}
	if strings.Contains(text, "std::regex") && !strings.Contains(text, "\"") && (strings.Contains(text, "(") || strings.Contains(text, "=")) {
		emit("regex-dos-dynamic-pattern", n)
	}
	if strings.Contains(text, "const_cast<") || strings.Contains(text, "const_cast <") {
		emit("const-cast-removing-constness", n)
	}
	if strings.Contains(text, "reinterpret_cast<") || strings.Contains(text, "reinterpret_cast <") {
		if (strings.Contains(text, "uint32_t") || strings.Contains(text, "<int>") || strings.Contains(text, "<long>") || strings.Contains(text, "<unsigned int>")) && !strings.Contains(text, "uintptr_t") {
			emit("reinterpret-cast-pointer-to-int", n)
		} else if (strings.Contains(text, "*") || strings.Contains(text, "Derived")) && !strings.Contains(text, "uintptr_t") {
			emit("reinterpret-cast-unrelated-classes", n)
		}
	}
	if strings.Contains(text, "auto_ptr") {
		emit("auto-ptr-deprecated", n)
	}
	if strings.Contains(text, "malloc(") || strings.Contains(text, "free(") {
		emit("malloc-free-in-cpp", n)
	}
	if (strings.Contains(text, "new ") && strings.Contains(text, "delete ")) || (strings.Contains(text, "new ") && !strings.Contains(text, "make_unique") && !strings.Contains(text, "make_shared")) {
		if strings.Contains(text, "delete ") {
			emit("raw-new-delete", n)
		}
	}
	if strings.Contains(text, "std::unique_ptr<") && strings.Contains(text, "new ") && strings.Contains(text, "[") && !strings.Contains(text, "[]") {
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
	if strings.Contains(text, "std::thread ") && !strings.Contains(text, ".join()") && !strings.Contains(text, ".detach()") {
		emit("thread-joinable-destructor", n)
	}
	if strings.Contains(text, "NULL") {
		if strings.Contains(text, "*") && !strings.Contains(text, "nullptr") {
			emit("null-macro-instead-of-nullptr", n)
		}
	}
	if strings.HasPrefix(strings.TrimSpace(text), "const int ") || strings.HasPrefix(strings.TrimSpace(text), "const size_t ") {
		if !strings.Contains(text, "constexpr") && strings.Contains(text, "=") {
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
	if (strings.Contains(text, "uid=") || strings.Contains(text, "ldap")) && strings.Contains(text, "+") && !strings.Contains(text, "escape_ldap") {
		emit("ldap-query-concatenation", n)
	}
	if (strings.Contains(text, "int counter = 0") || strings.Contains(text, "int shared_val")) && !strings.Contains(text, "atomic") && strings.Contains(string(src), "thread") {
		emit("shared-variable-no-synchronization", n)
	}
	if strings.Contains(text, "::iterator") && !strings.Contains(text, "typename ") {
		emit("missing-typename-dependent-type", n)
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
	if strings.Contains(text, "export template") {
		emit("export-template-obsolete", n)
	}
	if strings.Contains(text, "<N-1>") || strings.Contains(text, "<Depth-1>") || strings.Contains(text, "<Count-1>") {
		if !strings.Contains(string(src), "<0>") && !strings.Contains(string(src), "<1>") {
			emit("unbounded-template-recursion", n)
		}
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

func cppIsPrimitiveType(t string) bool {
	primitives := map[string]bool{
		"int": true, "unsigned int": true, "signed int": true,
		"short": true, "unsigned short": true, "signed short": true,
		"long": true, "unsigned long": true, "signed long": true,
		"long long": true, "unsigned long long": true,
		"char": true, "unsigned char": true, "signed char": true,
		"float": true, "double": true, "long double": true,
		"bool": true, "void": true, "size_t": true, "uint8_t": true,
		"uint16_t": true, "uint32_t": true, "uint64_t": true,
		"int8_t": true, "int16_t": true, "int32_t": true, "int64_t": true,
		"uintptr_t": true, "intptr_t": true, "std::string": true,
		"string": true, "std::string_view": true, "string_view": true,
		"std::span": true, "span": true,
	}
	return primitives[strings.TrimSpace(t)]
}
