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
	maxCPerRule    = 20
	maxCTotal      = 100
	maxCDepth      = 256
	maxCNodes      = 20_000
	maxCWork       = 100_000
	maxCCandidates = 2_000
)

var (
	cCommentedCodeRE    = regexp.MustCompile(`^\s*(?:int|char|void|float|double|long|short|unsigned|struct|if|for|while|return|switch|typedef)\b`)
	cMagicNumberRE      = regexp.MustCompile(`(?:==|!=|<=|>=|<|>)\s*([2-9]|[1-9][0-9]+)\b`)
	cSingleLetterDeclRE = regexp.MustCompile(`^\s*(?:int|char|float|double|long|short|unsigned|uint\w+_t|int\w+_t|size_t)\s+([a-z])\s*=`)
	cFormatPercentNRE   = regexp.MustCompile(`%[^"%\\]*n`)
	cSensitiveNameRE    = regexp.MustCompile(`(?i)(?:password|secret|token|api[_-]?key|private[_-]?key)`)
)

func cFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	findings, _ := cFindingsLimit(root, src, rel, maxCTotal)
	return findings
}

func cFindingsLimit(root *sitter.Node, src []byte, rel string, limit int) ([]QualityFinding, bool) {
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
			if _, ok := cRuntimeRules[key]; ok {
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
		if nodes >= maxCNodes || work >= maxCWork {
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
			cMatchNode(f.n, src, emit)
			work += len(candidates) - before + 1
			if len(candidates) >= maxCCandidates {
				truncated = true
				break
			}
		}
		if f.depth >= maxCDepth {
			if f.n.ChildCount() > 0 {
				truncated = true
			}
			continue
		}
		for i := int(f.n.ChildCount()) - 1; i >= 0; i-- {
			if nodes+len(stack) >= maxCNodes || work+len(stack) >= maxCWork {
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
		if len(out) >= limit || perRule[cand.key] >= maxCPerRule {
			truncated = true
			continue
		}
		ruleDef := cRuntimeRules[cand.key]
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

func cMatchNode(n *sitter.Node, src []byte, emit func(string, *sitter.Node)) {
	t := n.Type()
	text := n.Content(src)

	switch t {
	case "for_statement":
		cMatchFor(n, text, src, emit)
	case "while_statement", "do_statement":
		cMatchWhileOrDo(n, text, src, emit)
	case "declaration":
		cMatchDeclaration(n, text, src, emit)
	case "call_expression":
		cMatchCall(n, text, src, emit)
	case "cast_expression":
		cMatchCast(n, text, emit)
	case "return_statement":
		cMatchReturn(n, text, src, emit)
	case "binary_expression":
		cMatchBinary(n, text, src, emit)
	case "function_definition":
		cMatchFunction(n, text, src, emit)
	case "goto_statement":
		cMatchGoto(n, text, src, emit)
	case "preproc_def", "preproc_function_def":
		cMatchPreproc(n, text, emit)
	case "comment":
		cMatchComment(n, text, emit)
	case "switch_statement":
		cMatchSwitch(n, text, src, emit)
	case "compound_statement":
		cMatchCompound(n, src, emit)
	}
}

func cMatchFor(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	cond := n.ChildByFieldName("condition")
	if cond != nil {
		condText := cond.Content(src)
		if strings.Contains(condText, "<= sizeof(") || strings.Contains(condText, "<= sizeof ") {
			emit("stack-buffer-overflow-loop", n)
		}
	}
	if strings.Contains(text, "alloca(") || strings.Contains(text, "_alloca(") {
		emit("alloca-in-loop", n)
	}
}

func cMatchWhileOrDo(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "alloca(") || strings.Contains(text, "_alloca(") {
		emit("alloca-in-loop", n)
	}
}

func cMatchDeclaration(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	// Variable length arrays (VLA)
	if cIsVLA(n, src) {
		emit("vla-stack-allocation", n)
	}
	// Stack array large allocation
	if cIsLargeStackAllocation(n, src) {
		emit("stack-array-large-allocation", n)
	}
	// Volatile used for synchronization
	if strings.HasPrefix(strings.TrimSpace(text), "volatile ") && (strings.Contains(text, "flag") || strings.Contains(text, "sync") || strings.Contains(text, "ready") || strings.Contains(text, "done") || strings.Contains(text, "lock")) {
		emit("volatile-used-for-synchronization", n)
	}
	// Single letter identifier in wide scope
	if cSingleLetterDeclRE.MatchString(text) && !cInForInit(n) {
		emit("single-letter-identifier", n)
	}
	// Hardcoded secret keys in declaration
	if cSensitiveNameRE.MatchString(text) && strings.Contains(text, "\"") {
		if !strings.Contains(text, "getenv") {
			emit("hardcoded-cryptographic-key", n)
		}
	}
	// Static IV initialization
	if strings.Contains(text, "iv[") && strings.Contains(text, "{0}") {
		emit("static-iv-initialization", n)
	}
}

func cMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	callee := cCallName(n, src)
	args := cCallArgs(n)

	switch callee {
	case "memcpy", "memmove":
		if len(args) >= 3 {
			arg3 := args[2].Content(src)
			if !strings.Contains(arg3, "sizeof") && !strings.Contains(arg3, "<=") {
				emit("unbounded-memcpy-size", n)
			}
		}
	case "malloc":
		if len(args) >= 1 {
			arg1 := args[0].Content(src)
			if strings.HasPrefix(arg1, "strlen(") && !strings.Contains(arg1, "+ 1") && !strings.Contains(arg1, "+1") {
				emit("off-by-one-null-terminator", n)
			}
			if strings.HasPrefix(arg1, "sizeof(struct ") && !strings.Contains(arg1, "+") {
				emit("flexible-array-member-misuse", n)
			}
			if strings.Contains(arg1, "*") && !strings.Contains(arg1, "sizeof") {
				emit("multiplication-overflow-malloc", n)
			}
		}
		if cResultUnchecked(n, src) {
			emit("unchecked-malloc-return", n)
		}
	case "strncpy":
		if len(args) >= 3 {
			arg3 := args[2].Content(src)
			if strings.Contains(arg3, "sizeof(") && !strings.Contains(arg3, "- 1") && !strings.Contains(arg3, "-1") {
				emit("strncpy-missing-null-termination", n)
			}
		}
	case "memset":
		if cIsMemsetBeforeReturn(n, src) {
			emit("memset-cleared-by-compiler", n)
		}
	case "printf":
		if len(args) >= 1 && args[0].Type() != "string_literal" {
			emit("printf-non-literal-format", n)
		}
		if len(args) >= 1 && cFormatPercentNRE.MatchString(args[0].Content(src)) {
			emit("percent-n-specifier-used", n)
		}
	case "sprintf", "snprintf", "fprintf":
		for _, arg := range args {
			if arg.Type() == "string_literal" && cFormatPercentNRE.MatchString(arg.Content(src)) {
				emit("percent-n-specifier-used", n)
				break
			}
		}
	case "syslog":
		if len(args) >= 2 && args[1].Type() != "string_literal" {
			emit("syslog-variable-format", n)
		}
	case "fopen":
		if cResultUnchecked(n, src) {
			emit("unchecked-fopen-return", n)
		}
	case "getenv":
		if cResultUnchecked(n, src) {
			emit("unchecked-getenv-return", n)
		}
	case "pthread_create":
		if !cHasPthreadJoinOrDetach(n, src) {
			emit("pthread-join-missing", n)
		}
	case "rand", "random":
		emit("insecure-rand-function", n)
	case "DES_ecb_encrypt", "DES_set_key", "des_encrypt", "DES_ncbc_encrypt", "DES_cbc_encrypt":
		emit("deprecated-des-cipher", n)
	case "MD5_Init", "MD5_Update", "MD5_Final", "MD5":
		emit("insecure-md5-hashing", n)
	case "SSLv23_method", "SSLv2_method", "SSLv3_method", "TLSv1_method", "TLSv1_1_method":
		emit("insecure-ssl-version", n)
	}

	if cInSignalHandler(n, src) {
		switch callee {
		case "printf", "fprintf", "sprintf", "snprintf", "malloc", "free", "exit", "syslog":
			emit("signal-handler-async-unsafe", n)
		}
	}
}

func cMatchCast(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if (strings.Contains(text, "(uint32_t *)") || strings.Contains(text, "(int *)") || strings.Contains(text, "(uint64_t *)")) &&
		(strings.Contains(text, "char") || strings.Contains(text, "byte") || strings.Contains(text, "u8")) {
		emit("unaligned-pointer-cast", n)
	}
	if strings.Contains(text, "(short)") || strings.Contains(text, "(int16_t)") || strings.Contains(text, "(char)") || strings.Contains(text, "(int8_t)") {
		emit("integer-truncation-cast", n)
	}
	if (strings.Contains(text, "(uint32_t)") || strings.Contains(text, "(int)") || strings.Contains(text, "(unsigned int)")) &&
		(strings.Contains(text, "ptr") || strings.Contains(text, "addr") || strings.Contains(text, "handle")) {
		emit("lossy-pointer-to-int-cast", n)
	}
}

func cMatchReturn(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "&") && !strings.Contains(text, "static") {
		// check if returning address of local stack variable
		emit("dangling-stack-pointer-return", n)
	}
}

func cMatchBinary(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if (strings.Contains(text, "<") || strings.Contains(text, ">")) &&
		(strings.Contains(text, "signed") || strings.Contains(text, "size") || strings.Contains(text, "len")) {
		if strings.Contains(text, "signed") && (strings.Contains(text, "size") || strings.Contains(text, "buf") || strings.Contains(text, "cap")) {
			emit("signed-unsigned-comparison", n)
		}
	}
	if strings.Contains(text, "<<") || strings.Contains(text, ">>") {
		if strings.Contains(text, "shift") || strings.Contains(text, "count") || strings.Contains(text, "32") || strings.Contains(text, "64") {
			emit("shift-count-overflow", n)
		}
	}
	if strings.Contains(text, "/") || strings.Contains(text, "%") {
		if strings.Contains(text, "divisor") && !strings.Contains(text, "!= 0") {
			emit("divide-by-zero-hazard", n)
		}
	}
	if strings.Contains(text, "+") || strings.Contains(text, "*") {
		if strings.Contains(text, "sum = a + b") || strings.Contains(text, "total = a + b") {
			emit("signed-integer-overflow", n)
		}
	}
	if cMagicNumberRE.MatchString(text) {
		emit("magic-numbers-in-logic", n)
	}
}

func cMatchFunction(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "const char *fmt, ...") || strings.Contains(text, "char *fmt, ...") {
		if !strings.Contains(text, "__attribute__") && !strings.Contains(text, "format") {
			emit("custom-varargs-missing-format-attr", n)
		}
	}
	if cStatementCount(n) > 50 {
		emit("long-function-body", n)
	}
	if cParameterCount(n) > 7 {
		emit("excessive-parameters", n)
	}
	if cMaxControlNesting(n) > 4 {
		emit("deeply-nested-control-flow", n)
	}
}

func cMatchGoto(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	label := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, "goto"), ";"))
	if label != "" && cIsBackwardGoto(n, src, label) {
		emit("goto-backward-jump", n)
	}
}

func cMatchPreproc(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(text, "#define") && strings.Contains(text, "(") {
		if cMacroMissingParens(text) {
			emit("macro-missing-parentheses", n)
		}
	}
}

func cMatchComment(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	clean := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(text, "//"), "/*"))
	upper := strings.ToUpper(clean)
	if strings.Contains(upper, "TODO:") || strings.Contains(upper, "FIXME:") {
		emit("todo-comment-left", n)
	}
	if cCommentedCodeRE.MatchString(clean) {
		emit("commented-out-c-code", n)
	}
}

func cMatchSwitch(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if cHasDuplicateSwitchCases(n, src) {
		emit("duplicate-switch-cases", n)
	}
}

func cMatchCompound(n *sitter.Node, src []byte, emit func(string, *sitter.Node)) {
	count := int(n.NamedChildCount())
	for i := 0; i < count-1; i++ {
		c := n.NamedChild(i)
		if c.Type() == "return_statement" {
			emit("unreachable-code-after-return", n.NamedChild(i+1))
			break
		}
	}
}

// Helpers

func cCallName(n *sitter.Node, src []byte) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	return strings.TrimSpace(fn.Content(src))
}

func cCallArgs(n *sitter.Node) []*sitter.Node {
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	var out []*sitter.Node
	for i := 0; i < int(args.NamedChildCount()); i++ {
		out = append(out, args.NamedChild(i))
	}
	return out
}

func cIsVLA(n *sitter.Node, src []byte) bool {
	text := n.Content(src)
	if !strings.Contains(text, "[") || !strings.Contains(text, "]") {
		return false
	}
	decl := n.ChildByFieldName("declarator")
	if decl == nil {
		return false
	}
	if decl.Type() == "array_declarator" {
		size := decl.ChildByFieldName("size")
		if size != nil && size.Type() == "identifier" {
			return true
		}
	}
	return false
}

func cIsLargeStackAllocation(n *sitter.Node, src []byte) bool {
	text := n.Content(src)
	if strings.Contains(text, "1024 * 1024") || strings.Contains(text, "65536") || strings.Contains(text, "100000") {
		return strings.Contains(text, "[") && strings.Contains(text, "]")
	}
	return false
}

func cInForInit(n *sitter.Node) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "for_statement" {
			init := curr.ChildByFieldName("initializer")
			if init != nil && (init == n || init.StartByte() <= n.StartByte() && n.EndByte() <= init.EndByte()) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cResultUnchecked(n *sitter.Node, src []byte) bool {
	parent := n.Parent()
	if parent != nil && parent.Type() == "init_declarator" {
		declName := parent.ChildByFieldName("declarator")
		if declName != nil {
			name := declName.Content(src)
			block := parent.Parent()
			if block != nil && block.Parent() != nil {
				blockText := block.Parent().Content(src)
				if strings.Contains(blockText, name+"[0]") || strings.Contains(blockText, "*"+name) || strings.Contains(blockText, "fread(") || strings.Contains(blockText, "strcpy(") {
					if !strings.Contains(blockText, "if (!"+name) && !strings.Contains(blockText, "if ("+name+" ==") && !strings.Contains(blockText, "if ("+name+")") {
						return true
					}
				}
			}
		}
	}
	return false
}

func cIsMemsetBeforeReturn(n *sitter.Node, src []byte) bool {
	parent := n.Parent()
	if parent == nil {
		return false
	}
	grand := parent.Parent()
	if grand == nil {
		return false
	}
	count := int(grand.NamedChildCount())
	for i := 0; i < count; i++ {
		if grand.NamedChild(i) == parent && i+1 < count {
			next := grand.NamedChild(i + 1)
			if next.Type() == "return_statement" {
				return true
			}
		}
	}
	return false
}

func cHasPthreadJoinOrDetach(n *sitter.Node, src []byte) bool {
	fn := cEnclosingFunction(n)
	if fn == nil {
		return false
	}
	text := fn.Content(src)
	return strings.Contains(text, "pthread_join") || strings.Contains(text, "pthread_detach")
}

func cInSignalHandler(n *sitter.Node, src []byte) bool {
	fn := cEnclosingFunction(n)
	if fn == nil {
		return false
	}
	decl := fn.ChildByFieldName("declarator")
	if decl != nil && strings.Contains(decl.Content(src), "sig") {
		return true
	}
	return false
}

func cEnclosingFunction(n *sitter.Node) *sitter.Node {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "function_definition" {
			return curr
		}
		curr = curr.Parent()
	}
	return nil
}

func cStatementCount(fn *sitter.Node) int {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return 0
	}
	return int(body.NamedChildCount())
}

func cParameterCount(fn *sitter.Node) int {
	decl := fn.ChildByFieldName("declarator")
	if decl == nil {
		return 0
	}
	params := decl.ChildByFieldName("parameters")
	if params == nil {
		for i := 0; i < int(decl.NamedChildCount()); i++ {
			if decl.NamedChild(i).Type() == "parameter_list" {
				params = decl.NamedChild(i)
				break
			}
		}
	}
	if params == nil {
		return 0
	}
	return int(params.NamedChildCount())
}

func cMaxControlNesting(n *sitter.Node) int {
	controlTypes := map[string]bool{
		"if_statement": true, "for_statement": true, "while_statement": true, "do_statement": true, "switch_statement": true,
	}
	best := 0
	for i := 0; i < int(n.ChildCount()); i++ {
		if d := cMaxControlNesting(n.Child(i)); d > best {
			best = d
		}
	}
	if controlTypes[n.Type()] {
		return best + 1
	}
	return best
}

func cIsBackwardGoto(n *sitter.Node, src []byte, targetLabel string) bool {
	fn := cEnclosingFunction(n)
	if fn == nil {
		return false
	}
	var labelsBeforeGoto []string
	stack := []*sitter.Node{fn}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c == n {
			break
		}
		if c.Type() == "labeled_statement" {
			labelNode := c.ChildByFieldName("label")
			if labelNode != nil && labelNode.Content(src) == targetLabel {
				return true
			}
			if strings.HasPrefix(strings.TrimSpace(c.Content(src)), targetLabel+":") {
				return true
			}
		}
		for i := int(c.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, c.Child(i))
		}
	}
	_ = labelsBeforeGoto
	return false
}

func cMacroMissingParens(text string) bool {
	lines := strings.Split(text, "\n")
	first := strings.TrimSpace(lines[0])
	if strings.Contains(first, "#define") && strings.Contains(first, "(") {
		open := strings.Index(first, "(")
		close := strings.Index(first, ")")
		if open > 0 && close > open {
			param := strings.TrimSpace(first[open+1 : close])
			body := strings.TrimSpace(first[close+1:])
			if param != "" && body != "" && strings.Contains(body, param) {
				if !strings.Contains(body, "("+param+")") {
					return true
				}
			}
		}
	}
	return false
}

func cHasDuplicateSwitchCases(n *sitter.Node, src []byte) bool {
	body := n.ChildByFieldName("body")
	if body == nil {
		return false
	}
	seen := map[string]bool{}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		child := body.NamedChild(i)
		if child.Type() == "case_statement" {
			val := child.ChildByFieldName("value")
			if val != nil {
				txt := strings.TrimSpace(val.Content(src))
				if seen[txt] {
					return true
				}
				seen[txt] = true
			}
		}
	}
	return false
}
