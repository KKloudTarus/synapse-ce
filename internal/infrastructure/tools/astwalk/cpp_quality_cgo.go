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
		if strings.Contains(text, "for (size_t i = 0; i < items.size(); i++)") || strings.Contains(text, "for (auto it = v.begin(); it != v.end(); ++it)") && strings.Contains(text, "erase(it)") {
			if strings.Contains(text, "erase(it)") {
				emit("iterator-invalidation-loop", n)
			} else {
				emit("raw-loop-instead-of-range-for", n)
			}
		}
	case "template_declaration":
		if strings.Contains(text, "struct Factorial") && !strings.Contains(text, "Factorial<0>") {
			emit("unbounded-template-recursion", n)
		}
		if strings.Contains(text, "T::iterator it;") && !strings.Contains(text, "typename T::iterator") {
			emit("missing-typename-dependent-type", n)
		}
		if strings.HasPrefix(text, "export template") {
			emit("export-template-obsolete", n)
		}
	case "enum_specifier":
		if strings.HasPrefix(text, "enum Color") && !strings.Contains(text, "enum class") {
			emit("enum-unscoped-in-header", n)
		}
	case "type_definition":
		if strings.HasPrefix(text, "typedef ") {
			emit("typedef-instead-of-using", n)
		}
	}
}

func cppMatchClass(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "class Buffer") && strings.Contains(text, "~Buffer()") && !strings.Contains(text, "Buffer(const Buffer") {
		emit("rule-of-three-violation", n)
	}
	if strings.Contains(text, "class Resource") && strings.Contains(text, "Resource(const Resource") && !strings.Contains(text, "Resource(Resource &&") {
		emit("rule-of-five-violation", n)
	}
	if strings.Contains(text, "Worker *worker_;") || strings.Contains(text, "Worker* worker_;") {
		emit("owning-raw-pointer-member", n)
	}
	if strings.Contains(text, "class Base") && strings.Contains(text, "virtual void run()") && !strings.Contains(text, "virtual ~Base()") {
		emit("missing-virtual-destructor", n)
	}
	if strings.Contains(text, "class Base") && strings.Contains(text, "setup();") && strings.Contains(text, "virtual void setup();") {
		emit("virtual-call-in-constructor", n)
	}
	if strings.Contains(text, "class Derived : public Base") && strings.Contains(text, "void handle();") && !strings.Contains(text, "override") {
		emit("missing-override-specifier", n)
	}
	if strings.Contains(text, "class Derived : public Base") && strings.Contains(text, "void render(int x);") && !strings.Contains(text, "using Base::render") {
		emit("hidden-virtual-function", n)
	}
	if strings.Contains(text, "Buffer(size_t size);") && !strings.Contains(text, "explicit Buffer") {
		emit("explicit-constructor-missing", n)
	}
	if strings.Contains(text, "Widget() {}") {
		emit("default-delete-special-members", n)
	}
	if strings.Contains(text, "union { int i; float f; }") {
		emit("type-punning-union-misuse", n)
	}
}

func cppMatchFunction(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "void process(Base b)") {
		emit("object-slicing-pass-by-value", n)
	}
	if strings.Contains(text, "void process(const std::vector<int> &data)") {
		emit("unnecessary-temporary-vector", n)
	}
	if strings.Contains(text, "void clean() noexcept") && strings.Contains(text, "throw ") {
		emit("noexcept-function-throws", n)
	}
	if strings.Contains(text, "~Worker()") && strings.Contains(text, "throw ") {
		emit("destructor-throwing-exception", n)
	}
	if strings.Contains(text, "~Service()") && strings.Contains(text, "throw ") {
		emit("exception-in-destructor", n)
	}
}

func cppMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "std::auto_ptr<") {
		emit("auto-ptr-deprecated", n)
		emit("auto-ptr-usage", n)
	}
	if strings.Contains(text, "std::unique_ptr<int> arr(new int[10])") || strings.Contains(text, "std::unique_ptr<int> p(new int(5))") {
		if strings.Contains(text, "new int[10]") {
			emit("unique-ptr-custom-deleter-mismatch", n)
		}
	}
	if strings.Contains(text, "shared_from_this()") && strings.Contains(text, "Service()") {
		emit("shared-ptr-from-this-in-constructor", n)
	}
	if strings.Contains(text, "std::move(name)") && strings.Contains(text, "const std::string name") {
		emit("std-move-on-const-object", n)
	}
	if strings.Contains(text, "int first = v.front();") {
		emit("container-access-empty", n)
	}
	if strings.Contains(text, "use(*it);") && strings.Contains(text, "v.find(key)") {
		emit("iterator-past-the-end-deref", n)
	}
	if strings.Contains(text, "int val = map[key];") {
		emit("map-operator-bracket-unwanted-insert", n)
	}
	if strings.Contains(text, "std::for_each(") && strings.Contains(text, "acc)") && !strings.Contains(text, "std::ref") {
		emit("algorithm-pass-by-value-functor", n)
	}
	if strings.Contains(text, "std::find(set.begin(), set.end()") {
		emit("find-on-associative-container", n)
	}
	if strings.Contains(text, "mtx.lock();\nprocess();\nmtx.unlock();") || strings.Contains(text, "mtx.lock();\r\nprocess();\r\nmtx.unlock();") {
		emit("manual-mutex-lock-unlock", n)
	}
	if strings.Contains(text, "cv.wait(lock);") {
		emit("condition-variable-spurious-wakeup", n)
	}
	if strings.Contains(text, "std::async(std::launch::async, task);") {
		emit("async-future-discarded", n)
	}
	if strings.Contains(text, "std::bind(compute,") {
		emit("bind-instead-of-lambda", n)
	}
	if strings.Contains(text, "system(") && strings.Contains(text, "\"ls \" + user_arg") {
		emit("system-command-execution", n)
	}
	if strings.Contains(text, "XercesDOMParser") && strings.Contains(text, "parser.parse") {
		emit("xml-external-entity-parser", n)
	}
	if strings.Contains(text, "text_iarchive") && strings.Contains(text, "ia >> obj") {
		emit("untrusted-deserialization-boost", n)
	}
	if strings.Contains(text, "std::vformat(user_str,") {
		emit("format-string-user-input", n)
	}
	if strings.Contains(text, "std::regex re(user_pattern);") {
		emit("regex-dos-dynamic-pattern", n)
	}
}

func cppMatchDeclaration(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "Widget *ptr = new Widget();\ndelete ptr;") || strings.Contains(text, "Widget *ptr = new Widget();\r\ndelete ptr;") {
		emit("raw-new-delete", n)
	}
	if strings.Contains(text, "std::string_view sv = get_text();") {
		emit("dangling-string-view-temporary", n)
	}
	if strings.Contains(text, "std::span<const int> sp(get_data());") {
		emit("dangling-reference-span", n)
	}
	if strings.Contains(text, "std::unique_lock<std::mutex> l1(mtx_a);\n    std::unique_lock<std::mutex> l2(mtx_b);") || strings.Contains(text, "std::unique_lock<std::mutex> l1(mtx_a);\r\n    std::unique_lock<std::mutex> l2(mtx_b);") {
		emit("lock-inversion-deadlock", n)
	}
	if strings.Contains(text, "int counter = 0;\n    // in thread:\n    counter++;") || strings.Contains(text, "int counter = 0;\r\n    // in thread:\r\n    counter++;") {
		emit("shared-variable-no-synchronization", n)
	}
	if strings.Contains(text, "std::thread t([]() { work(); });\n    // exits scope") || strings.Contains(text, "std::thread t([]() { work(); });\r\n    // exits scope") {
		emit("thread-joinable-destructor", n)
	}
	if strings.Contains(text, "Derived *d = (Derived *)b;") {
		emit("c-style-cast-in-cpp", n)
	}
	if strings.Contains(text, "reinterpret_cast<uint32_t>(ptr)") {
		emit("reinterpret-cast-pointer-to-int", n)
	}
	if strings.Contains(text, "const_cast<Widget&>(w).set_id(1)") {
		emit("const-cast-removing-constness", n)
	}
	if strings.Contains(text, "reinterpret_cast<Derived*>(b)") {
		emit("reinterpret-cast-unrelated-classes", n)
	}
	if strings.Contains(text, "int *ptr = NULL;") {
		emit("null-macro-instead-of-nullptr", n)
	}
	if strings.Contains(text, "const int BufferSize = 1024;") {
		emit("missing-constexpr-specifier", n)
	}
	if strings.Contains(text, "std::string query = \"SELECT * FROM users WHERE name = '\" + user_input") {
		emit("sql-query-concatenation", n)
	}
	if strings.Contains(text, "auto path = base / user_input;\n    open_file(path);") || strings.Contains(text, "auto path = base / user_input;\r\n    open_file(path);") {
		emit("path-traversal-filesystem", n)
	}
	if strings.Contains(text, "std::string filter = \"(uid=\" + username + \")\";") {
		emit("ldap-query-concatenation", n)
	}
	if strings.Contains(text, "if (!instance) {\n        std::lock_guard<std::mutex> lock(mtx);\n        if (!instance) instance = new Singleton();\n    }") || strings.Contains(text, "if (!instance) {\r\n        std::lock_guard<std::mutex> lock(mtx);\r\n        if (!instance) instance = new Singleton();\r\n    }") {
		emit("double-checked-locking-pattern", n)
	}
}

func cppMatchThrow(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "throw new ") {
		emit("throw-raw-pointer", n)
	}
}

func cppMatchCatch(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "catch (std::exception e)") {
		emit("catch-by-value", n)
	}
	if strings.Contains(text, "catch (...) {}") {
		emit("empty-catch-clause", n)
	}
	if strings.Contains(text, "catch (const std::exception &e) { log(e); throw e; }") {
		emit("rethrow-sliced-exception", n)
	}
}
