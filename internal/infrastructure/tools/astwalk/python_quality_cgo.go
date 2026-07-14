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
	"mutable-default": {"reliability", "python-mutable-default-argument", "CWE-398", "high", "Mutable default argument", "A mutable default value is shared by every call. Use None and create the value inside the function."},
	"bare-except":     {"reliability", "python-bare-except", "CWE-396", "medium", "Bare except catches every exception", "Catching every exception can hide unexpected failures. Catch the expected exception type instead."},
	"return-finally":  {"reliability", "python-return-in-finally", "CWE-584", "medium", "Control flow in finally suppresses exceptions", "Returning or breaking from finally can discard an active exception or return value."},
	"duplicate-dict":  {"reliability", "python-duplicate-dict-key", "CWE-561", "medium", "Duplicate dictionary key", "A later dictionary entry overwrites an earlier entry with the same literal key."},
	"assert":          {"sast", "python-assert-for-validation", "CWE-617", "medium", "Runtime assert used for validation", "Assertions can be disabled at runtime. Raise an explicit exception for input validation."},
	"none":            {"quality", "python-eq-none", "", "low", "Compare None with is", "Use is None or is not None for singleton identity checks."},
	"star-import":     {"quality", "python-star-import", "", "low", "Wildcard import", "Wildcard imports hide a module's dependencies and can overwrite names."},
	"open":            {"quality", "python-open-no-context", "", "low", "File opened without a context manager", "Use with open(...) so the file closes reliably when an error occurs."},
	"type-eq":         {"quality", "python-type-eq-vs-isinstance", "", "low", "Use isinstance instead of type equality", "isinstance supports subclasses while a direct type comparison does not."},
	"global":          {"quality", "python-global-statement", "", "low", "Global statement", "Global state makes data flow harder to understand and test."},
	"args":            {"quality", "python-too-many-args", "", "low", "Function has too many arguments", "A long parameter list makes an API hard to call and evolve. Group related values into an object."},
	"f-log":           {"quality", "python-f-string-logging", "", "info", "Eager f-string logging", "Use logger parameter formatting so message construction is deferred when the log level is disabled."},
	"len-zero":        {"quality", "python-len-eq-zero", "", "info", "Compare a collection directly", "Use collection truthiness instead of comparing len(collection) to zero."},
	"unused-import":   {"quality", "python-unused-import", "", "info", "Unused import", "Remove imports that are not referenced by the module."},
	"broad-raise":     {"quality", "python-broad-raise", "", "low", "Broad Exception raised", "Raise a specific exception type so callers can handle the failure deliberately."},
}

var (
	noneCompareRE = regexp.MustCompile(`(?s)(==|!=)\s*None\b|\bNone\s*(==|!=)`)
	typeCompareRE = regexp.MustCompile(`(?s)\btype\s*\([^)]*\)\s*(==|!=)`)
	lenZeroRE     = regexp.MustCompile(`(?s)\blen\s*\([^)]*\)\s*(==|!=)\s*0\b|\b0\s*(==|!=)\s*len\s*\(`)
	fStringRE     = regexp.MustCompile(`(?s)\bf["']`)
	broadRaiseRE  = regexp.MustCompile(`(?s)^\s*raise\s+(Exception|BaseException)\s*(\(|$)`)
)

// QualityFor parses Python files and returns the precision-biased seed quality rules. It deliberately does
// not attempt alias, import-resolution, or interprocedural analysis.
func QualityFor(ctx context.Context, root string) (Quality, error) {
	out := Quality{Findings: []QualityFinding{}}
	truncated, err := walkSource(ctx, root, func(rel, lang string, content []byte) {
		if lang != "Python" {
			return
		}
		tree := parseRoot(ctx, specs[lang], content)
		if tree == nil {
			return
		}
		out.Findings = append(out.Findings, pythonFindings(tree, content, rel)...)
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
		case "except_clause":
			if strings.HasPrefix(strings.TrimSpace(text), "except:") {
				out = append(out, pythonFinding("bare-except", n, rel))
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
		case "comparison_operator":
			if noneCompareRE.MatchString(text) {
				out = append(out, pythonFinding("none", n, rel))
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
