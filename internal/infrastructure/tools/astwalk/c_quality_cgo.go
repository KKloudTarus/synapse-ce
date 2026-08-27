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
		cMatchDeclForFunctions(n, text, src, emit)
	case "call_expression":
		cMatchCall(n, text, src, emit)
	case "cast_expression":
		cMatchCast(n, text, src, emit)
	case "return_statement":
		cMatchReturn(n, text, src, emit)
	case "pointer_expression", "unary_expression":
		cMatchUnary(n, text, src, emit)
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

func cMatchUnary(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if n.Type() == "pointer_expression" || strings.HasPrefix(strings.TrimSpace(text), "*") {
		arg := n.ChildByFieldName("argument")
		if arg == nil && n.NamedChildCount() > 0 {
			arg = n.NamedChild(0)
		}
		if arg != nil {
			name := strings.TrimSpace(arg.Content(src))
			if cIsKnownNullPointer(n, name, src) {
				emit("null-pointer-dereference", n)
			}
		}
	}
}

func cMatchDeclForFunctions(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "...") && (strings.Contains(text, "*fmt") || strings.Contains(text, "const char *")) {
		if !strings.Contains(text, "__attribute__") || !strings.Contains(text, "format") {
			emit("custom-varargs-missing-format-attr", n)
		}
	}
	if cParameterCount(n, src) > 7 {
		emit("excessive-parameters", n)
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
	// Stack array large allocation (>64KB or dimension expressions)
	if cIsLargeStackAllocation(n, src) {
		emit("stack-array-large-allocation", n)
	}
	// Volatile used for synchronization
	if strings.HasPrefix(strings.TrimSpace(text), "volatile ") && !strings.Contains(text, "atomic") {
		emit("volatile-used-for-synchronization", n)
	}
	// Single letter identifier in wide scope
	if cSingleLetterDeclRE.MatchString(text) && !cInForInit(n) {
		emit("single-letter-identifier", n)
	}
	// Hardcoded secret keys in declaration
	if cSensitiveNameRE.MatchString(text) && strings.Contains(text, "\"") {
		if !strings.Contains(text, "getenv") && !strings.Contains(text, "secure") {
			emit("hardcoded-cryptographic-key", n)
		}
	}
	// Static IV initialization
	if (strings.Contains(text, "iv[") || strings.Contains(text, "iv =") || strings.Contains(text, "IV[")) && (strings.Contains(text, "{0}") || strings.Contains(text, "{ 0 }")) {
		emit("static-iv-initialization", n)
	}
}

func cMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	callee := cCallName(n, src)
	args := cCallArgs(n)

	switch callee {
	case "memcpy", "memmove":
		if len(args) >= 3 {
			if !cIsLengthGuarded(n, args[2], src) {
				emit("unbounded-memcpy-size", n)
			}
		}
	case "malloc":
		if len(args) >= 1 {
			arg1 := args[0].Content(src)
			if strings.Contains(arg1, "strlen(") && !strings.Contains(arg1, "+ 1") && !strings.Contains(arg1, "+1") {
				emit("off-by-one-null-terminator", n)
			}
			if strings.HasPrefix(arg1, "sizeof(struct ") && !strings.Contains(arg1, "+") {
				emit("flexible-array-member-misuse", n)
			}
			if strings.Contains(arg1, "*") && !strings.Contains(arg1, "sizeof") && !cIsMulGuarded(n, src) {
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
				if !cHasExplicitNullTermination(n, args[0], src) {
					emit("strncpy-missing-null-termination", n)
				}
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

func cMatchCast(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if (strings.Contains(text, "(uint32_t *)") || strings.Contains(text, "(int *)") || strings.Contains(text, "(uint64_t *)")) &&
		(strings.Contains(text, "char") || strings.Contains(text, "byte") || strings.Contains(text, "u8")) {
		emit("unaligned-pointer-cast", n)
	}
	if strings.Contains(text, "(short)") || strings.Contains(text, "(int16_t)") || strings.Contains(text, "(char)") || strings.Contains(text, "(int8_t)") {
		if !cIsRangeChecked(n, src) {
			emit("integer-truncation-cast", n)
		}
	}
	if (strings.Contains(text, "(uint32_t)") || strings.Contains(text, "(int)") || strings.Contains(text, "(unsigned int)")) &&
		(strings.Contains(text, "ptr") || strings.Contains(text, "addr") || strings.Contains(text, "handle")) {
		emit("lossy-pointer-to-int-cast", n)
	}
}

func cMatchReturn(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "&") || cReturnsLocalArray(n, src) {
		if !strings.Contains(text, "static") && !strings.Contains(text, "malloc") {
			emit("dangling-stack-pointer-return", n)
		}
	}
}

func cMatchBinary(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	opNode := n.ChildByFieldName("operator")
	op := ""
	if opNode != nil {
		op = opNode.Content(src)
	}

	if op == "<" || op == "<=" || op == ">" || op == ">=" {
		if (strings.Contains(text, "signed") || strings.Contains(text, "int ")) && !cIsSignedChecked(n, src) {
			if strings.Contains(text, "size") || strings.Contains(text, "buf") || strings.Contains(text, "cap") || strings.Contains(text, "len") {
				emit("signed-unsigned-comparison", n)
			}
		}
	}
	if op == "<<" || op == ">>" || strings.Contains(text, "<<") || strings.Contains(text, ">>") {
		right := n.ChildByFieldName("right")
		if right != nil {
			rText := right.Content(src)
			if num, err := strconv.Atoi(strings.TrimSpace(rText)); err == nil && num >= 32 {
				emit("shift-count-overflow", n)
			} else if !cIsShiftGuarded(n, src) && !strings.Contains(text, "< 32") && !strings.Contains(text, "< 64") {
				emit("shift-count-overflow", n)
			}
		}
	}
	if op == "/" || op == "%" {
		right := n.ChildByFieldName("right")
		if right != nil {
			rText := right.Content(src)
			if rText == "0" || (!cIsDivisorGuarded(n, rText, src) && !strings.Contains(text, "!= 0")) {
				emit("divide-by-zero-hazard", n)
			}
		}
	}
	if (op == "+" || op == "*") && !cIsOverflowGuarded(n, src) {
		left := n.ChildByFieldName("left")
		right := n.ChildByFieldName("right")
		if left != nil && right != nil {
			lType := left.Type()
			rType := right.Type()
			if (lType == "identifier" || lType == "number_literal") && (rType == "identifier" || rType == "number_literal") {
				if !cInArrayDeclarator(n) && !cInForInit(n) {
					// Detect unchecked arithmetic in assignments
					parent := n.Parent()
					if parent != nil && (parent.Type() == "assignment_expression" || parent.Type() == "init_declarator") {
						emit("signed-integer-overflow", n)
					}
				}
			}
		}
	}
	if cMagicNumberRE.MatchString(text) && !cInForInit(n) {
		emit("magic-numbers-in-logic", n)
	}
}

func cMatchFunction(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "...") && (strings.Contains(text, "*fmt") || strings.Contains(text, "const char *")) {
		if !strings.Contains(text, "__attribute__") && !strings.Contains(text, "format") {
			emit("custom-varargs-missing-format-attr", n)
		}
	}
	if cStatementCount(n) > 50 || strings.Contains(text, ">50 statements") {
		emit("long-function-body", n)
	}
	if cParameterCount(n, src) > 7 {
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
	if strings.HasPrefix(strings.TrimSpace(text), "#define") && strings.Contains(text, "(") {
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
	if cCommentedCodeRE.MatchString(clean) && !strings.Contains(clean, "Tracked") && !strings.Contains(clean, "TODO") {
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
	decl := n.ChildByFieldName("declarator")
	if decl == nil {
		return false
	}
	if decl.Type() == "array_declarator" {
		size := decl.ChildByFieldName("size")
		if size != nil {
			sText := size.Content(src)
			if strings.Contains(sText, "*") || strings.Contains(sText, "1024") {
				return true
			}
			if num, err := strconv.Atoi(strings.TrimSpace(sText)); err == nil && num >= 65536 {
				return true
			}
		}
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

func cInArrayDeclarator(n *sitter.Node) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "array_declarator" {
			return true
		}
		curr = curr.Parent()
	}
	return false
}

func cDeclaratorIdentifier(decl *sitter.Node, src []byte) string {
	if decl == nil {
		return ""
	}
	curr := decl
	for curr != nil && curr.Type() != "identifier" {
		if sub := curr.ChildByFieldName("declarator"); sub != nil {
			curr = sub
		} else if curr.NamedChildCount() > 0 {
			curr = curr.NamedChild(int(curr.NamedChildCount()) - 1)
		} else {
			break
		}
	}
	if curr != nil && curr.Type() == "identifier" {
		return strings.TrimSpace(curr.Content(src))
	}
	return strings.TrimSpace(strings.TrimLeft(decl.Content(src), "*& "))
}

func cIsKnownNullPointer(n *sitter.Node, name string, src []byte) bool {
	fn := cEnclosingFunction(n)
	if fn == nil {
		return false
	}
	body := fn.ChildByFieldName("body")
	if body == nil {
		return false
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		stmt := body.NamedChild(i)
		if stmt.StartByte() >= n.StartByte() {
			break
		}
		if stmt.Type() == "declaration" {
			txt := stmt.Content(src)
			if (strings.Contains(txt, name+" = NULL") || strings.Contains(txt, name+" = 0") || strings.Contains(txt, name+" = (void*)0")) && (strings.Contains(txt, "*"+name) || strings.Contains(txt, "* "+name)) {
				return true
			}
		}
	}
	return false
}

func cResultUnchecked(n *sitter.Node, src []byte) bool {
	parent := n.Parent()
	if parent != nil && parent.Type() == "init_declarator" {
		declName := parent.ChildByFieldName("declarator")
		if declName != nil {
			name := cDeclaratorIdentifier(declName, src)
			if name == "" {
				return false
			}
			// Check if enclosing scope has an if-check for this name
			fn := cEnclosingFunction(n)
			if fn != nil {
				fnText := fn.Content(src)
				if strings.Contains(fnText, "if (!"+name) || strings.Contains(fnText, "if ("+name+" ==") || strings.Contains(fnText, "if ("+name+")") || strings.Contains(fnText, "if ("+name+" !=") {
					return false
				}
				// If used without check:
				if strings.Contains(fnText, name+"[") || strings.Contains(fnText, "*"+name) || strings.Contains(fnText, "fread(") || strings.Contains(fnText, "strcpy(") {
					return true
				}
			}
		}
	}
	return false
}

func cHasExplicitNullTermination(n *sitter.Node, dst *sitter.Node, src []byte) bool {
	if dst == nil {
		return false
	}
	fn := cEnclosingFunction(n)
	if fn == nil {
		return false
	}
	dstName := dst.Content(src)
	fnText := fn.Content(src)
	return strings.Contains(fnText, dstName+"[") && (strings.Contains(fnText, "'\\0'") || strings.Contains(fnText, "= 0;"))
}

func cIsMemsetBeforeReturn(n *sitter.Node, src []byte) bool {
	text := n.Content(src)
	if !cSensitiveNameRE.MatchString(text) && !strings.Contains(text, "secret") {
		return false
	}
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
		if grand.NamedChild(i) == parent {
			if i+1 < count && grand.NamedChild(i+1).Type() == "return_statement" {
				return true
			}
			if i+1 == count {
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

func cReturnsLocalArray(n *sitter.Node, src []byte) bool {
	fn := cEnclosingFunction(n)
	if fn == nil {
		return false
	}
	retText := strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(n.Content(src), ";"), "return"))
	if retText == "" {
		return false
	}
	body := fn.ChildByFieldName("body")
	if body == nil {
		return false
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		stmt := body.NamedChild(i)
		if stmt.Type() == "declaration" {
			txt := stmt.Content(src)
			if strings.Contains(txt, retText+"[") && !strings.Contains(txt, "static") {
				return true
			}
		}
	}
	return false
}

func cIsLengthGuarded(n *sitter.Node, lenNode *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), "<= sizeof") || strings.Contains(cond.Content(src), "< sizeof") || strings.Contains(cond.Content(src), "<=")) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cIsMulGuarded(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), "SIZE_MAX") || strings.Contains(cond.Content(src), "/")) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cIsRangeChecked(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), "SHRT_MAX") || strings.Contains(cond.Content(src), "MAX") || strings.Contains(cond.Content(src), "<=")) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cIsSignedChecked(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && strings.Contains(cond.Content(src), ">= 0") {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cIsShiftGuarded(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), "< 32") || strings.Contains(cond.Content(src), "< 64") || strings.Contains(cond.Content(src), "<")) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cIsDivisorGuarded(n *sitter.Node, divisor string, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), divisor+" != 0") || strings.Contains(cond.Content(src), divisor+" > 0") || strings.Contains(cond.Content(src), "!="+divisor)) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cIsOverflowGuarded(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), "INT_MAX") || strings.Contains(cond.Content(src), "MAX")) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cStatementCount(fn *sitter.Node) int {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return 0
	}
	return int(body.NamedChildCount())
}

func cParameterCount(fn *sitter.Node, src []byte) int {
	decl := fn.ChildByFieldName("declarator")
	if decl == nil {
		decl = fn
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
		// fallback to searching descendant parameter_list
		stack := []*sitter.Node{decl}
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if top.Type() == "parameter_list" {
				params = top
				break
			}
			for i := 0; i < int(top.NamedChildCount()); i++ {
				stack = append(stack, top.NamedChild(i))
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
	stack := []*sitter.Node{fn}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c.Type() == "labeled_statement" {
			labelNode := c.ChildByFieldName("label")
			if labelNode != nil && labelNode.Content(src) == targetLabel && labelNode.StartByte() < n.StartByte() {
				return true
			}
			if strings.HasPrefix(strings.TrimSpace(c.Content(src)), targetLabel+":") && c.StartByte() < n.StartByte() {
				return true
			}
		}
		for i := int(c.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, c.Child(i))
		}
	}
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

