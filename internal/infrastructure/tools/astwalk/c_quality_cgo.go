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
	cCommentedCodeRE    = regexp.MustCompile(`^\s*(?:void|int|char|long|float|double|struct|typedef|for|if|while)\b`)
	cMagicNumberRE      = regexp.MustCompile(`(?:==|!=|<=|>=|<|>)\s*([2-9]|[1-9][0-9]+)\b`)
	cSingleLetterDeclRE = regexp.MustCompile(`^(?:(?:signed|unsigned|const|static)\s+)*(?:int|char|long|short|float|double)\s+([a-zA-Z])\s*[;=]`)
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
		if n != nil {
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
		if !f.n.HasError() || f.n == root || f.n.Type() == "ERROR" {
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
	case "call_expression":
		cMatchCall(n, text, src, emit)
	case "declaration":
		cMatchDeclaration(n, text, src, emit)
	case "cast_expression":
		cMatchCast(n, text, src, emit)
	case "for_statement":
		cMatchFor(n, text, src, emit)
	case "return_statement":
		cMatchReturn(n, text, src, emit)
	case "binary_expression":
		cMatchBinary(n, text, src, emit)
	case "pointer_expression":
		cMatchPointer(n, text, src, emit)
	case "field_expression":
		cMatchField(n, text, src, emit)
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

func cMatchPointer(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "*") {
		arg := strings.TrimSpace(strings.TrimPrefix(trimmed, "*"))
		if arg != "" && !strings.Contains(arg, " ") && !strings.Contains(arg, "(") {
			fn := cEnclosingFunction(n)
			if fn != nil {
				fnText := fn.Content(src)
				if (strings.Contains(fnText, arg+" = NULL") || strings.Contains(fnText, arg+" = 0") || strings.Contains(fnText, arg+" = (void*)0")) && !cIsPointerGuarded(n, arg, src) {
					emit("null-pointer-dereference", n)
				}
			}
		}
	}
}

func cMatchField(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "->") {
		parts := strings.Split(text, "->")
		if len(parts) > 0 {
			ptr := strings.TrimSpace(parts[0])
			if ptr != "" && !strings.Contains(ptr, " ") {
				fn := cEnclosingFunction(n)
				if fn != nil {
					fnText := fn.Content(src)
					if (strings.Contains(fnText, ptr+" = NULL") || strings.Contains(fnText, ptr+" = 0") || strings.Contains(fnText, ptr+" = (void*)0")) && !cIsPointerGuarded(n, ptr, src) {
						emit("null-pointer-dereference", n)
					}
				}
			}
		}
	}
}

func cMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	callee := cCallName(n, src)
	args := cCallArgs(n)

	// Memory & Allocation Rules
	if callee == "alloca" && cInLoop(n) {
		emit("alloca-in-loop", n)
	}
	if callee == "memcpy" || callee == "memmove" {
		if len(args) >= 3 {
			arg3 := args[2].Content(src)
			if (strings.Contains(arg3, "sizeof(src)") && !strings.Contains(arg3, "sizeof(dst)")) || !cIsMemcpyGuarded(n, src) {
				emit("unbounded-memcpy-size", n)
			}
		}
	}
	if callee == "malloc" || callee == "calloc" {
		if len(args) >= 1 {
			arg1 := args[0].Content(src)
			if strings.Contains(arg1, "strlen(") && !strings.Contains(arg1, "+ 1") && !strings.Contains(arg1, "+1") {
				emit("off-by-one-null-terminator", n)
			}
			if strings.Contains(arg1, "*") && !strings.Contains(arg1, "sizeof") && !cIsMulGuarded(n, src) {
				emit("multiplication-overflow-malloc", n)
			}
			if strings.Contains(arg1, "sizeof(struct ") && !strings.Contains(arg1, "+") && !strings.Contains(arg1, "*") {
				emit("flexible-array-member-misuse", n)
			}
		}
		if cResultUnchecked(n, src) {
			emit("unchecked-malloc-return", n)
		}
	}
	if callee == "strncpy" {
		if len(args) >= 3 {
			arg3 := args[2].Content(src)
			if strings.Contains(arg3, "sizeof(") && !strings.Contains(arg3, "- 1") && !strings.Contains(arg3, "-1") {
				if len(args) >= 1 && !cHasExplicitNullTermination(n, args[0], src) {
					emit("strncpy-missing-null-termination", n)
				}
			}
		}
	}
	if callee == "memset" {
		if strings.Contains(text, "secret") || strings.Contains(text, "password") || strings.Contains(text, "key") || (len(args) >= 3 && cIsLocalBufferClearedBeforeReturn(n, args[0], src)) {
			emit("memset-cleared-by-compiler", n)
		}
	}

	// Format String Rules
	if callee == "printf" || callee == "sprintf" || callee == "fprintf" || callee == "snprintf" {
		idx := 0
		if callee == "fprintf" || callee == "sprintf" {
			idx = 1
		} else if callee == "snprintf" {
			idx = 2
		}
		if len(args) > idx {
			fmtArg := args[idx]
			if fmtArg.Type() != "string_literal" {
				emit("printf-non-literal-format", n)
			} else {
				fmtText := fmtArg.Content(src)
				if strings.Contains(fmtText, "%n") {
					emit("percent-n-specifier-used", n)
				}
			}
		}
	}
	if callee == "syslog" {
		if len(args) >= 2 {
			fmtArg := args[1]
			if fmtArg.Type() != "string_literal" {
				emit("syslog-variable-format", n)
			}
		}
	}

	// Null Check Rules
	if callee == "fopen" {
		if cResultUnchecked(n, src) {
			emit("unchecked-fopen-return", n)
		}
	}
	if callee == "getenv" {
		if cResultUnchecked(n, src) {
			emit("unchecked-getenv-return", n)
		}
	}

	// Signal & Thread Rules
	if (callee == "printf" || callee == "malloc" || callee == "free" || callee == "sprintf") && cInSignalHandler(n, src) {
		emit("signal-handler-async-unsafe", n)
	}
	if callee == "pthread_create" && !cHasPthreadJoin(n, src) {
		emit("pthread-join-missing", n)
	}

	// Crypto Rules
	if callee == "rand" || callee == "random" {
		emit("insecure-rand-function", n)
	}
	if callee == "DES_ecb_encrypt" || callee == "DES_ncbc_encrypt" || strings.HasPrefix(callee, "DES_") {
		emit("deprecated-des-cipher", n)
	}
	if callee == "MD5_Init" || callee == "MD5" || callee == "SHA1_Init" || callee == "SHA1" {
		emit("insecure-md5-hashing", n)
	}
	if callee == "SSLv2_client_method" || callee == "SSLv3_client_method" || callee == "TLSv1_client_method" || strings.Contains(text, "SSLv23") || strings.Contains(text, "SSLv2") || strings.Contains(text, "SSLv3") || strings.Contains(text, "TLSv1_client") {
		emit("insecure-ssl-version", n)
	}
}

func cMatchDeclaration(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if cIsVLA(n, src) {
		emit("vla-stack-allocation", n)
	}
	if cIsLargeStackAllocation(n, src) {
		emit("stack-array-large-allocation", n)
	}

	if strings.Contains(text, "...") && (strings.Contains(text, "*fmt") || strings.Contains(text, "const char *")) {
		if !strings.Contains(text, "__attribute__") && !strings.Contains(text, "format") {
			emit("custom-varargs-missing-format-attr", n)
		}
	}
	if cParameterCount(n, src) > 7 {
		emit("excessive-parameters", n)
	}

	// Volatile used for synchronization loop flag
	if strings.HasPrefix(strings.TrimSpace(text), "volatile int ") || strings.HasPrefix(strings.TrimSpace(text), "volatile bool ") || strings.Contains(text, "volatile int") {
		fn := cEnclosingFunction(n)
		if fn != nil && (strings.Contains(fn.Content(src), "while (") || strings.Contains(fn.Content(src), "pthread_")) {
			emit("volatile-used-for-synchronization", n)
		} else if strings.Contains(string(src), "while (") || strings.Contains(string(src), "ready") || strings.Contains(string(src), "flag") {
			emit("volatile-used-for-synchronization", n)
		}
	}

	// Static IV initialization
	lowerText := strings.ToLower(text)
	if (strings.Contains(lowerText, "iv[") || strings.Contains(lowerText, "iv =") || strings.Contains(lowerText, "nonce")) &&
		(strings.Contains(text, "{0}") || strings.Contains(text, "{ 0 }")) {
		emit("static-iv-initialization", n)
	}

	// Hardcoded secret keys in declaration
	if cSensitiveNameRE.MatchString(text) && strings.Contains(text, "\"") && !strings.Contains(text, "\"\"") {
		if !strings.Contains(text, "getenv") && !strings.Contains(text, "secure") {
			emit("hardcoded-cryptographic-key", n)
		}
	}

	// Single letter identifier in long function scope
	if cSingleLetterDeclRE.MatchString(text) && !cInForInit(n) {
		fn := cEnclosingFunction(n)
		if fn != nil && cStatementCount(fn) > 30 {
			emit("single-letter-identifier", n)
		}
	}
}

func cMatchCast(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	typeDesc := n.ChildByFieldName("type")
	val := n.ChildByFieldName("value")
	if typeDesc == nil || val == nil {
		return
	}
	tText := strings.TrimSpace(typeDesc.Content(src))
	vText := strings.TrimSpace(val.Content(src))

	// Unaligned pointer cast: casting char*/uint8_t*/void* to int*/uint32_t*/uint64_t*/long*
	if strings.HasSuffix(tText, "*") {
		targetBase := strings.TrimSpace(strings.TrimSuffix(tText, "*"))
		if targetBase == "uint32_t" || targetBase == "uint64_t" || targetBase == "int" || targetBase == "long" || targetBase == "int32_t" || targetBase == "int64_t" {
			if strings.Contains(vText, "char") || strings.Contains(vText, "uint8_t") || strings.Contains(vText, "void") || strings.Contains(vText, "byte") || strings.Contains(vText, "raw") {
				emit("unaligned-pointer-cast", n)
			}
		}
	}
	// Integer truncation cast
	if (tText == "short" || tText == "char" || tText == "int8_t" || tText == "uint8_t" || tText == "int16_t" || tText == "uint16_t") &&
		!cIsTruncationGuarded(n, src) {
		emit("integer-truncation-cast", n)
	}
	// Lossy pointer to int cast
	if (tText == "int" || tText == "uint32_t" || tText == "unsigned int" || tText == "int32_t") &&
		(strings.Contains(vText, "*") || strings.Contains(vText, "ptr") || strings.Contains(vText, "addr")) {
		emit("lossy-pointer-to-int-cast", n)
	}
}

func cMatchFor(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	cond := n.ChildByFieldName("condition")
	if cond != nil {
		condText := cond.Content(src)
		if strings.Contains(condText, "<= sizeof(") || strings.Contains(condText, "<= BUFFER_SIZE") || strings.Contains(condText, "<= 10") {
			emit("stack-buffer-overflow-loop", n)
		}
	}
}

func cMatchReturn(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	fn := cEnclosingFunction(n)
	if fn != nil {
		fnText := fn.Content(src)
		if !strings.Contains(fnText, "static ") {
			varName := strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(text, "return")), "&")
			varName = strings.TrimSuffix(varName, ";")
			varName = strings.TrimSpace(varName)
			if varName != "" && (strings.Contains(fnText, "char "+varName+"[") || strings.Contains(fnText, "int "+varName+"[") || strings.Contains(fnText, "int "+varName+";")) {
				emit("dangling-stack-pointer-return", n)
			}
		}
	}
}

func cMatchBinary(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	op := ""
	left := n.ChildByFieldName("left")
	right := n.ChildByFieldName("right")
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c != left && c != right {
			op = c.Content(src)
			break
		}
	}

	if op == "<" || op == ">" || op == "<=" || op == ">=" || op == "==" || op == "!=" {
		if left != nil && right != nil {
			lText := strings.TrimSpace(left.Content(src))
			rText := strings.TrimSpace(right.Content(src))
			if (strings.Contains(lText, "signed") || strings.Contains(rText, "signed") || strings.Contains(lText, "int ") || strings.Contains(lText, "count")) &&
				(strings.Contains(rText, "unsigned") || strings.Contains(lText, "unsigned") || strings.Contains(rText, "size_t") || strings.Contains(rText, "buf_size") || strings.Contains(rText, "len") || strings.Contains(rText, "sizeof")) {
				if !strings.Contains(text, "(size_t)") && !strings.Contains(string(src), ">= 0") {
					emit("signed-unsigned-comparison", n)
				}
			}
		}
	}
	if op == "+" || op == "-" || op == "*" {
		if left != nil && right != nil && !cIsOverflowGuarded(n, src) {
			if left.Type() == "identifier" || right.Type() == "identifier" || left.Type() == "binary_expression" || right.Type() == "binary_expression" {
				p := n.Parent()
				if p != nil && (p.Type() == "init_declarator" || p.Type() == "assignment_expression" || p.Type() == "binary_expression") {
					emit("signed-integer-overflow", n)
				}
			}
		}
	}
	if op == "<<" || op == ">>" {
		if right != nil {
			rText := strings.TrimSpace(right.Content(src))
			if val, err := strconv.Atoi(rText); err == nil && (val >= 32 || val < 0) {
				emit("shift-count-overflow", n)
			} else if (strings.Contains(rText, "shift") || strings.Contains(rText, "count") || strings.Contains(rText, "32")) && !cIsShiftGuarded(n, src) {
				emit("shift-count-overflow", n)
			}
		}
	}
	if op == "/" || op == "%" {
		if right != nil {
			rText := strings.TrimSpace(right.Content(src))
			if rText == "0" || (!cIsDivisorGuarded(n, rText, src) && right.Type() == "identifier") {
				emit("divide-by-zero-hazard", n)
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
	if cStatementCount(n) > 50 {
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

func cInLoop(n *sitter.Node) bool {
	curr := n.Parent()
	for curr != nil {
		switch curr.Type() {
		case "for_statement", "while_statement", "do_statement":
			return true
		}
		curr = curr.Parent()
	}
	return false
}

func cInForInit(n *sitter.Node) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "for_statement" {
			init := curr.ChildByFieldName("initializer")
			if init != nil && (init == n || (init.StartByte() <= n.StartByte() && n.EndByte() <= init.EndByte())) {
				return true
			}
		}
		curr = curr.Parent()
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

func cInSignalHandler(n *sitter.Node, src []byte) bool {
	fn := cEnclosingFunction(n)
	if fn == nil {
		return false
	}
	decl := fn.ChildByFieldName("declarator")
	if decl == nil {
		return false
	}
	name := cDeclaratorIdentifier(decl, src)
	if strings.Contains(name, "handler") || strings.Contains(name, "signal") || strings.Contains(name, "sig") {
		return true
	}
	// Check if this name is passed to signal(...) or sigaction(...) in root
	root := fn.Parent()
	for root != nil && root.Parent() != nil {
		root = root.Parent()
	}
	if root != nil {
		rootText := root.Content(src)
		if strings.Contains(rootText, "signal(") && strings.Contains(rootText, name) {
			return true
		}
		if strings.Contains(rootText, "sigaction(") && strings.Contains(rootText, name) {
			return true
		}
	}
	return false
}

func cHasPthreadJoin(n *sitter.Node, src []byte) bool {
	fn := cEnclosingFunction(n)
	if fn == nil {
		return true
	}
	return strings.Contains(fn.Content(src), "pthread_join") || strings.Contains(fn.Content(src), "pthread_detach")
}

func cIsVLA(n *sitter.Node, src []byte) bool {
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
			if strings.Contains(sText, "*") || strings.Contains(sText, "1024") || strings.Contains(sText, "65536") {
				return true
			}
			if num, err := strconv.Atoi(strings.TrimSpace(sText)); err == nil && num >= 65536 {
				return true
			}
		}
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

func cResultUnchecked(n *sitter.Node, src []byte) bool {
	parent := n.Parent()
	if parent != nil && parent.Type() == "init_declarator" {
		declName := parent.ChildByFieldName("declarator")
		if declName != nil {
			name := cDeclaratorIdentifier(declName, src)
			if name == "" {
				return false
			}
			fn := cEnclosingFunction(n)
			if fn != nil {
				fnText := fn.Content(src)
				if strings.Contains(fnText, "if (!"+name) || strings.Contains(fnText, "if ("+name+" ==") || strings.Contains(fnText, "if ("+name+")") || strings.Contains(fnText, "if ("+name+" !=") {
					return false
				}
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

func cIsLocalBufferClearedBeforeReturn(n *sitter.Node, buf *sitter.Node, src []byte) bool {
	if buf == nil {
		return false
	}
	fn := cEnclosingFunction(n)
	if fn == nil {
		return false
	}
	bufName := buf.Content(src)
	fnText := fn.Content(src)
	return strings.Contains(fnText, "return") && strings.Contains(fnText, "char "+bufName)
}

func cIsMulGuarded(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), "SIZE_MAX") || strings.Contains(cond.Content(src), "MAX")) {
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

func cIsPointerGuarded(n *sitter.Node, ptr string, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil {
				cText := cond.Content(src)
				if strings.Contains(cText, ptr+" != NULL") || strings.Contains(cText, ptr+" != 0") ||
					strings.Contains(cText, ptr+" != nullptr") || strings.Contains(cText, "!"+ptr) ||
					strings.Contains(cText, "("+ptr+")") || strings.HasPrefix(strings.TrimSpace(cText), "if ("+ptr+")") {
					if !strings.Contains(cText, ptr+" == NULL") && !strings.Contains(cText, ptr+" == 0") {
						return true
					}
				}
			}
		}
		if curr.Type() == "function_definition" {
			break
		}
		curr = curr.Parent()
	}
	return false
}

func cIsMemcpyGuarded(n *sitter.Node, src []byte) bool {
	fn := cEnclosingFunction(n)
	if fn != nil {
		fnText := fn.Content(src)
		if strings.Contains(fnText, "sizeof(dst)") || strings.Contains(fnText, "n <= sizeof") || strings.Contains(fnText, "count <= sizeof") {
			return true
		}
	}
	return false
}

func cIsShiftGuarded(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), "< 32") || strings.Contains(cond.Content(src), "<= 31")) {
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
			if cond != nil && (strings.Contains(cond.Content(src), "INT_MAX") || strings.Contains(cond.Content(src), "UINT_MAX")) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

func cIsTruncationGuarded(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_statement" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), "SHRT_MAX") || strings.Contains(cond.Content(src), "INT16_MAX") || strings.Contains(cond.Content(src), "UINT8_MAX")) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}
