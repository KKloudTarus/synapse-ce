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
	maxSwiftPerRule    = 20
	maxSwiftTotal      = 100
	maxSwiftDepth      = 256
	maxSwiftNodes      = 20_000
	maxSwiftWork       = 100_000
	maxSwiftCandidates = 2_000
)

var (
	swiftIdentifierRE      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	swiftIntegerRE         = regexp.MustCompile(`^[0-9][0-9_]*$`)
	swiftHTTPURLRE         = regexp.MustCompile(`^\s*"http://[^"\\]+"\s*$`)
	swiftSensitiveNameRE   = regexp.MustCompile(`(?i)(?:^|[^a-z])(?:password|passphrase|secret|token|api[\s_-]?key|private[\s_-]?key)(?:$|[^a-z])`)
	swiftCommentedCodeRE   = regexp.MustCompile(`^\s*(?:let|var|func|if|for|while|return|guard|switch|class|struct)\b`)
	swiftPublicDeclRE      = regexp.MustCompile(`\bpublic\s+(?:func|class|struct|enum|protocol|var|let)\b`)
	swiftStringLiteralRE   = regexp.MustCompile(`^\s*"(?:[^"\\]|\\.)*"\s*$`)
	swiftRangeRE           = regexp.MustCompile(`^\s*([0-9][0-9_]*)\s*\.\.\.\s*([0-9][0-9_]*)\s*$`)
	swiftStringKeyRE       = regexp.MustCompile(`\[\s*"[^"\\]+"\s*\]`)
	swiftMagicNumberRE     = regexp.MustCompile(`(?:==|!=|<=|>=|<|>)\s*([2-9]|[1-9][0-9]+)\b`)
	swiftTooManyParamRE    = regexp.MustCompile(`(?:[A-Za-z_][A-Za-z0-9_]*\s*:\s*[^,()]+,\s*){7}`)
	swiftUnsafePtrReturnRE = regexp.MustCompile(`^\s*return\s+Unsafe(?:Mutable)?Pointer\s*\(`)
)

// swiftFindings performs only node-local checks. A parser recovery node is not
// trusted, but its valid descendants are still walked so one malformed construct
// cannot suppress findings in a valid sibling.
func swiftFindings(root *sitter.Node, src []byte, rel string) ([]QualityFinding, bool) {
	return swiftFindingsLimit(root, src, rel, maxSwiftTotal)
}

// swiftFindingsLimit keeps Swift work bounded both per file and for the
// repository-wide budget supplied by QualityFor.
func swiftFindingsLimit(root *sitter.Node, src []byte, rel string, limit int) ([]QualityFinding, bool) {
	return swiftFindingsLimitWithCounts(root, src, rel, limit, nil)
}

type swiftCaps struct {
	depth, nodes, work, candidates int
}

var defaultSwiftCaps = swiftCaps{
	depth: maxSwiftDepth, nodes: maxSwiftNodes, work: maxSwiftWork, candidates: maxSwiftCandidates,
}

func swiftFindingsLimitWithCounts(root *sitter.Node, src []byte, rel string, limit int, existing map[string]int) ([]QualityFinding, bool) {
	return swiftFindingsLimitWithCaps(root, src, rel, limit, existing, defaultSwiftCaps)
}

func swiftFindingsLimitWithCaps(root *sitter.Node, src []byte, rel string, limit int, existing map[string]int, caps swiftCaps) ([]QualityFinding, bool) {
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
			if _, ok := swiftRuntimeRules[key]; ok {
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
		if nodes >= caps.nodes || work >= caps.work {
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
			swiftMatchNode(f.n, src, emit)
			work += len(candidates) - before + 1
			if len(candidates) >= caps.candidates {
				truncated = true
				break
			}
		}
		if f.depth >= caps.depth {
			if f.n.ChildCount() > 0 {
				truncated = true
			}
			continue
		}
		for i := int(f.n.ChildCount()) - 1; i >= 0; i-- {
			if nodes+len(stack) >= caps.nodes || work+len(stack) >= caps.work {
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
	perRule := map[string]int{}
	for key, count := range existing {
		perRule[key] = count
	}
	out := make([]QualityFinding, 0, min(limit, 16))
	seen := map[string]bool{}
	for _, candidate := range candidates {
		line := int(candidate.n.StartPoint().Row) + 1
		identity := candidate.key + "\x00" + strconv.Itoa(line)
		if seen[identity] {
			continue
		}
		seen[identity] = true
		if len(out) >= limit || perRule[candidate.key] >= maxSwiftPerRule {
			truncated = true
			continue
		}
		meta := swiftRuntimeRules[candidate.key]
		out = append(out, QualityFinding{Kind: meta.kind, Rule: meta.rule, CWE: meta.cwe, Severity: meta.severity, Title: meta.title, Description: meta.description, File: rel, Line: line})
		perRule[candidate.key]++
	}
	if existing != nil {
		for key, count := range perRule {
			existing[key] = count
		}
	}
	return out, truncated
}

// swiftMatchNode never examines an ancestor's source. Text checks are confined
// to the grammar construct that establishes their context (a call, declaration,
// expression, statement, or comment), which prevents repeated ancestor matches.
func swiftMatchNode(n *sitter.Node, src []byte, emit func(string, *sitter.Node)) {
	text := strings.TrimSpace(n.Content(src))
	if text == "" {
		return
	}
	typ := n.Type()
	if len(text) > 8192 {
		switch typ {
		case "function_declaration", "protocol_function_declaration", "init_declaration", "deinit_declaration", "subscript_declaration":
			if body := n.ChildByFieldName("body"); body != nil && !body.HasError() && swiftStatementCount(body) > 50 {
				emit("long-function", n)
			}
			if swiftDeepControlFlow(n) {
				emit("deep-nesting", n)
			}
		case "class_declaration", "struct_declaration", "enum_declaration":
			if swiftTypeMemberCount(n) > 40 {
				emit("large-type", n)
			}
		}
		return
	}
	switch typ {
	case "comment", "multiline_comment":
		comment := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(text, "//"), "/*"))
		if strings.Contains(strings.ToUpper(comment), "TODO:") {
			emit("todo-comment", n)
		}
		if swiftCommentedCodeRE.MatchString(comment) {
			emit("commented-code", n)
		}
		return
	case "bang":
		// The Swift grammar gives postfix unwrap its own bang token. Operators
		// such as != are equality_expression children, not this node.
		if p := n.Parent(); p != nil && (p.Type() == "postfix_expression" || p.Type() == "navigation_expression") {
			emit("force-unwrap", n)
			if swiftStringKeyRE.MatchString(p.Content(src)) {
				emit("dictionary-force-lookup", n)
			}
		}
		return
	case "try_expression":
		if strings.HasPrefix(text, "try!") {
			emit("force-try", n)
		}
		if strings.HasPrefix(text, "try?") {
			if swiftStandaloneTryExpression(n) {
				emit("try-optional-discard", n)
			}
			if p := n.Parent(); p != nil && strings.Contains(p.Content(src), "_ =") {
				emit("error-discarded", n)
			}
			if strings.Contains(text, "Task.sleep") {
				emit("task-sleep-error-discarded", n)
			}
		}
		return
	case "as_expression":
		if strings.Contains(text, " as NSString") {
			emit("nsstring-legacy", n)
		}
		if strings.Contains(text, " as! ") || strings.HasSuffix(text, " as!") {
			emit("force-cast", n)
			if swiftAnyObjectCast(n, src) {
				emit("anyobject-cast", n)
			}
			if strings.Contains(text, ".Type") {
				emit("metatype-cast", n)
			}
			if strings.Contains(text, "View") {
				emit("type-erasure-cast", n)
			}
		}
		return
	case "dictionary_literal":
		if strings.Contains(text, "kSecAttrAccessible: kSecAttrAccessibleAlways") {
			emit("keychain-accessible-always", n)
		}
		if swiftDuplicateDictionaryKey(text) {
			emit("duplicate-dictionary-key", n)
		}
		return
	case "switch_entry":
		if strings.HasPrefix(text, "case ") && strings.TrimSpace(strings.TrimSuffix(text, ";")) != "" && strings.HasSuffix(strings.TrimSpace(strings.TrimSuffix(text, ";")), ": break") {
			emit("empty-switch-case", n)
		}
		return
	case "switch_statement":
		if swiftDuplicateSwitchCase(n, src) {
			emit("duplicate-switch-case", n)
		}
		return
	case "call_suffix":
		if swiftLiteralCallSuffix(n, src) {
			emit("array-index-literal", n)
		}
		return
	case "postfix_expression":
		if strings.HasSuffix(text, "!") && swiftStringKeyRE.MatchString(text) {
			emit("dictionary-force-lookup", n)
		}
		if swiftStringKeyRE.MatchString(text) && swiftSettingsReceiver(text) {
			emit("stringly-typed-key", n)
		}
		return
	case "assignment":
		swiftMatchAssignment(n, text, emit)
		if swiftStringKeyRE.MatchString(text) && swiftSettingsReceiver(text) {
			emit("stringly-typed-key", n)
		}
		return
	case "property_declaration":
		swiftMatchLocalDeclaration(n, text, emit)
		swiftMatchProperty(n, src, text, emit)
		return
	case "attribute":
		if strings.HasPrefix(text, "@available(") && strings.Contains(text, "deprecated:") {
			emit("deprecated-availability", n)
		}
		return
	case "for_statement":
		if swiftBridgeHeavyLoop(n, src) {
			emit("autoreleasepool-missing", n)
		}
		if swiftMainQueueLoop(n, src) {
			emit("main-thread-heavy-loop", n)
		}
		return
	case "navigation_expression":
		if strings.HasPrefix(text, "self.") && swiftStoredSelfMember(n, src) {
			emit("redundant-self", n)
		}
		if strings.Contains(text, " as NSString") && strings.HasSuffix(text, ".length") {
			emit("string-size", n)
		}
		if strings.Contains(text, ".sorted(") && strings.HasSuffix(text, ".first") {
			emit("sort-first", n)
		}
		return
	case "type_annotation":
		if strings.Count(text, "&") >= 3 {
			emit("protocol-composition-long", n)
		}
		if strings.Contains(text, ": any ") {
			emit("existential-any", n)
		}
		return
	case "parameter":
		if strings.Count(text, "&") >= 3 {
			emit("protocol-composition-long", n)
		}
		if strings.Contains(text, " any ") {
			emit("existential-any", n)
		}
		if strings.Contains(text, "!") {
			emit("implicitly-unwrapped-parameter", n)
		}
		return
	case "while_statement":
		if swiftConstantCondition(n, src) {
			emit("constant-condition", n)
		}
		return
	case "guard_statement":
		if !swiftGuardElseExits(n, src) {
			emit("guard-without-exit", n)
		}
		return
	case "statements":
		swiftMatchStatements(n, src, emit)
		if p := n.Parent(); p != nil && strings.HasPrefix(strings.TrimSpace(p.Content(src)), "defer") {
			if n.NamedChildCount() == 0 {
				emit("empty-defer", p)
			}
			if swiftControlFlowExit(n.Content(src)) {
				emit("return-in-defer", p)
			}
		}
		return
	case "call_expression":
		if text == "defer { }" {
			emit("empty-defer", n)
		}
		if text == "defer { return }" {
			emit("return-in-defer", n)
		}
		swiftMatchCall(n, src, text, emit)
		return
	case "defer_statement":
		if swiftBody(text) == "" {
			emit("empty-defer", n)
		}
		if swiftControlFlowExit(swiftBody(text)) {
			emit("return-in-defer", n)
		}
		return
	case "catch_block":
		body := swiftBody(text)
		if body == "" {
			emit("empty-catch", n)
		}
		if strings.HasPrefix(text, "catch {") {
			emit("broad-catch", n)
		}
		if body == "print(error)" {
			emit("catch-print-only", n)
		}
		if strings.Contains(body, "throw") && !strings.Contains(body, "error") {
			emit("error-message-lost", n)
		}
		return
	case "control_transfer_statement":
		if strings.HasPrefix(text, "throw ") && strings.Contains(text, "NSError(") {
			emit("throw-generic-error", n)
		}
		if swiftUnsafePtrReturnRE.MatchString(text) {
			emit("unsafe-pointer-escape", n)
		}
		return
	case "range_expression":
		if m := swiftRangeRE.FindStringSubmatch(text); len(m) == 3 && swiftLiteralGreater(m[1], m[2]) {
			emit("invalid-range", n)
		}
		return
	case "nil_coalescing_expression":
		if left, right, ok := swiftBinarySides(text, "??"); ok && left == right && swiftIdentifierRE.MatchString(left) {
			emit("nil-coalescing-self", n)
		}
		return
	case "equality_expression", "comparison_expression":
		if left, right, ok := swiftEqualitySides(text); ok && left == right && swiftIdentifierRE.MatchString(left) {
			emit("comparison-self", n)
		}
		if strings.Contains(text, "Optional.none") {
			emit("optional-equality-nil", n)
		}
		if strings.Contains(text, ".count") && (strings.HasSuffix(text, "== 0") || strings.HasSuffix(text, "!= 0")) {
			emit("count-zero", n)
		}
		return
	case "if_statement":
		if swiftRedundantOptionalBind(n, src) {
			emit("redundant-optional-bind", n)
		}
		if swiftConstantCondition(n, src) {
			emit("constant-condition", n)
		}
		return
	case "value_binding_pattern":
		return
	case "function_declaration", "protocol_function_declaration", "init_declaration", "deinit_declaration", "subscript_declaration":
		swiftMatchFunction(n, src, text, emit)
		if swiftDeepControlFlow(n) {
			emit("deep-nesting", n)
		}
		return
	case "class_declaration", "struct_declaration", "enum_declaration":
		if swiftTypeMemberCount(n) > 40 {
			emit("large-type", n)
		}
		if strings.HasPrefix(strings.TrimSpace(text), "actor ") && swiftActorHasBlockingCall(n, src) {
			emit("actor-blocking-call", n)
		}
		return
	case "line_string_literal", "multi_line_string_literal", "raw_string_literal":
		if swiftHTTPURLRE.MatchString(text) && swiftCallContext(n, src, "URL") {
			emit("http-url", n)
		}
		return
	case "integer_literal":
		if swiftMagicNumberNode(n, src) {
			emit("magic-number", n)
		}
		return
	}
}

func swiftMatchCall(n *sitter.Node, src []byte, text string, emit func(string, *sitter.Node)) {
	name := swiftCallName(n, src)
	args := swiftCallArguments(n, src)
	argsText := swiftArgumentsText(args)
	switch {
	case name == "fatalError":
		emit("fatal-error", n)
	case name == "preconditionFailure":
		emit("precondition-failure", n)
	case name == "assert":
		emit("assert-production", n)
	case name == "print" || name == "debugPrint" || name == "NSLog" || name == "os_log":
		emit("print-logging", n)
		if swiftSensitiveNameRE.MatchString(argsText) {
			emit("sensitive-log", n)
		}
	case name == "NSSelectorFromString":
		emit("selector-string", n)
	case strings.HasSuffix(name, ".perform"):
		emit("perform-selector", n)
	case strings.HasSuffix(name, ".setValue") && swiftLabeledArgumentValue(args, "forKey") != "":
		emit("kvc-string", n)
	case name == "NSURL":
		emit("nsurl-legacy", n)
	case name == "NSData":
		emit("nsdata-legacy", n)
	case name == "dispatch_once":
		emit("dispatch-once", n)
	case strings.HasSuffix(name, ".openURL"):
		emit("uiapplication-openurl", n)
	case strings.HasSuffix(name, ".path") && strings.Contains(name, "Bundle"):
		emit("bundle-path", n)
	case name == "DateFormatter":
		if swiftInsideFunction(n) {
			emit("foundation-date-formatter", n)
			emit("repeated-dateformatter", n)
		}
	case strings.Contains(name, "NSKeyedUnarchiver.unarchiveObject"):
		emit("unsafe-deserialization", n)
	case name == "NSPredicate" && strings.Contains(argsText, "\\("):
		emit("predicate-format", n)
	case strings.HasSuffix(name, ".loadHTMLString") && strings.Contains(argsText, "\\("):
		emit("html-string", n)
	case name == "NSRegularExpression" && !swiftRegexLiteral(swiftLabeledArgumentValue(args, "pattern")):
		emit("regex-from-input", n)
	case strings.HasSuffix(name, ".evaluateJavaScript"):
		emit("webview-javascript", n)
	case strings.Contains(name, "UserDefaults.standard.set") && swiftSensitiveNameRE.MatchString(argsText):
		emit("userdefaults-sensitive", n)
	case strings.Contains(name, "URLCredential") && swiftLabeledArgumentValue(args, "trust") != "" && swiftUnconditionalTrustCredential(n, src):
		emit("tls-trust-all", n)
	case strings.Contains(name, "Task.sleep") && strings.HasPrefix(strings.TrimSpace(text), "try?"):
		emit("task-sleep-error-discarded", n)
	case strings.HasSuffix(name, ".wait") && strings.Contains(name, "semaphore"):
		emit("semaphore-wait-main", n)
	case strings.Contains(name, "DispatchQueue.main.sync"):
		emit("main-queue-sync", n)
	case strings.HasSuffix(name, ".wait") && strings.Contains(name, "group"):
		emit("dispatch-group-wait", n)
	case strings.Contains(name, "waitUntilAllOperationsAreFinished"):
		emit("operation-queue-main-block", n)
	case strings.Contains(name, "Task.detached") && swiftClosureCapturesSelf(n, src):
		emit("detached-task-self", n)
	case name == "Task" && !swiftAssigned(n):
		emit("task-unstructured", n)
	case (name == "random" || name == "rand" || name == "drand48") && swiftSecurityContext(n, src):
		emit("insecure-random", n)
	case strings.HasSuffix(name, ".addObserver") && strings.Contains(name, "NotificationCenter") && swiftLabeledArgumentValue(args, "selector") != "":
		emit("notification-observer-unremoved", n)
	case strings.Contains(name, "Timer.scheduledTimer") && swiftLabeledArgumentValue(args, "repeats") == "true" && swiftClosureCapturesSelf(n, src):
		emit("timer-retain-cycle", n)
	case strings.HasSuffix(name, ".evaluatePolicy") && swiftArgumentValue(args, 0) == ".deviceOwnerAuthentication" && swiftLAContextReceiver(name, n, src):
		emit("biometric-fallback", n)
	case swiftLoggerCall(name) && swiftSensitiveNameRE.MatchString(argsText):
		emit("sensitive-log", n)
	case name == "NSString" || strings.HasSuffix(name, " as NSString"):
		emit("nsstring-legacy", n)
	case strings.HasSuffix(name, ".contains") && swiftInsideLoop(n) && swiftLocalArrayReceiver(n, src, name):
		emit("array-contains-loop", n)
	case (name == "Double" || name == "Float" || name == "CGFloat") && swiftIntegerDivisionArgument(argsText):
		emit("integer-division", n)
	case strings.Contains(name, "Data") && swiftStaticIVContext(n, src, argsText):
		emit("static-iv", n)
	case name == "Data" && strings.TrimSpace(swiftArgumentValue(args, 0)) == "data":
		emit("data-copy", n)
	case strings.Contains(name, "Notification.Name") && swiftFirstArgumentIsString(args):
		emit("notification-string-name", n)
	case strings.Contains(name, "HTTPMethod") && swiftFirstArgumentIsString(args):
		emit("raw-value-enum-string", n)
	}
	if name == "URL" && strings.Contains(argsText, "\\(") {
		emit("url-interpolation", n)
	}
	if swiftSQLSink(name) && swiftSQLDynamicArgument(n, src, args) {
		emit("sql-concat", n)
	}
	if swiftDynamicShellInvocation(n, src, name, args) {
		emit("command-shell", n)
	}
	if strings.Contains(name, "FileHandle") {
		emit("file-handle-unclosed", n)
	}
	if strings.Contains(name, "DispatchSource.make") {
		emit("dispatch-source-unbalanced", n)
	}
	if strings.Contains(name, "withCheckedContinuation") && swiftContinuationResumeMissing(text) {
		emit("continuation-resume-missing", n)
	}
	if strings.Contains(name, "Insecure.MD5") || strings.Contains(name, "Insecure.SHA1") || strings.Contains(name, "CC_MD5") || strings.Contains(name, "CC_SHA1") {
		emit("weak-hash", n)
	}
	if strings.Contains(argsText, ".ecbMode") {
		emit("ecb-mode", n)
	}
	if strings.Contains(name, "NSString") && strings.HasSuffix(name, ".length") {
		emit("string-size", n)
	}
	if strings.Contains(name, ".sorted") && strings.Contains(text, ".first") {
		emit("sort-first", n)
	}
	if strings.Contains(name, ".filter") && strings.Contains(text, ".map") && !strings.Contains(text, ".lazy") {
		emit("map-filter-chain", n)
	}
}

func swiftMatchAssignment(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	left, right, ok := swiftBinarySides(text, "=")
	if ok && left == right && swiftIdentifierRE.MatchString(left) {
		emit("self-assignment", n)
	}
	if strings.Contains(text, " + ") && (strings.Contains(strings.ToLower(left), "path") || strings.Contains(strings.ToLower(left), "url")) {
		emit("path-concat", n)
	}
	if strings.Contains(right, " + ") && (strings.Contains(strings.ToLower(left), "path") || strings.Contains(strings.ToLower(left), "url")) {
		emit("path-concat", n)
	}
	if strings.Contains(text, "self.") && strings.Contains(right, "{") && strings.Contains(right, "self.") && !strings.Contains(right, "[weak self]") && !strings.Contains(right, "[unowned self]") {
		emit("retain-cycle-self", n)
	}
	if strings.Contains(text, "pasteboard.string") && swiftSensitiveNameRE.MatchString(right) {
		emit("pasteboard-sensitive", n)
	}
	if strings.Contains(text, "kSecAttrAccessible") && strings.Contains(right, "kSecAttrAccessibleAlways") {
		emit("keychain-accessible-always", n)
	}
	if strings.Contains(text, "kSecAttrAccessible: kSecAttrAccessibleAlways") {
		emit("keychain-accessible-always", n)
	}
	if strings.Contains(text, "server.enabled") && strings.Contains(right, "true") {
		emit("debug-server", n)
	}
	if strings.Contains(text, ".count") && strings.Contains(right, "0") {
		emit("count-zero", n)
	}
	if strings.Contains(text, "text +=") && swiftInsideLoop(n) {
		emit("string-concat-loop", n)
	}
	if strings.Contains(text, "_ = try?") {
		emit("error-discarded", n)
	}
}

func swiftMatchProperty(n *sitter.Node, src []byte, text string, emit func(string, *sitter.Node)) {
	if swiftTypeAnnotationIUO(n, src) {
		if swiftInsideFunction(n) {
			emit("implicitly-unwrapped-local", n)
		} else {
			emit("implicitly-unwrapped-optional", n)
		}
	}
	if strings.Contains(text, ": Bool?") {
		emit("optional-boolean", n)
	}
	if strings.Contains(text, ": [") && strings.Contains(text, "]?") {
		emit("optional-collection", n)
	}
	if strings.Contains(text, "@objc dynamic") {
		emit("objc-dynamic", n)
	}
	if strings.Contains(text, " + ") && (strings.Contains(strings.ToLower(text), "path") || strings.Contains(strings.ToLower(text), "url")) {
		emit("path-concat", n)
	}
}

func swiftTypeAnnotationIUO(n *sitter.Node, src []byte) bool {
	stack := []*sitter.Node{n}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current != n && current.Type() == "type_annotation" && strings.HasSuffix(strings.TrimSpace(current.Content(src)), "!") {
			return true
		}
		for i := 0; i < int(current.ChildCount()); i++ {
			stack = append(stack, current.Child(i))
		}
	}
	return false
}

func swiftMatchFunction(n *sitter.Node, src []byte, text string, emit func(string, *sitter.Node)) {
	header := swiftFunctionHeader(n, src)
	if swiftTooManyParamRE.MatchString(header) {
		emit("too-many-parameters", n)
	}
	if body := n.ChildByFieldName("body"); body != nil && !body.HasError() && swiftStatementCount(body) > 50 {
		emit("long-function", n)
	}
	if swiftInoutCapturedByEscapingClosure(n, src) {
		emit("inout-escaping", n)
	}
	if strings.Contains(header, "-> (") && strings.Count(header, ",") >= 3 {
		emit("tuple-return-many", n)
	}
	if swiftExactReturnType(n, src, "Any") {
		emit("opaque-result-erased", n)
	}
	if swiftHasExactAnyParameter(n, src) {
		emit("any-without-protocol", n)
	}
	if swiftPublicDeclRE.MatchString(header) && !swiftHasDocumentation(n, src) {
		emit("public-undocumented", n)
	}
}

func swiftFunctionHeader(n *sitter.Node, src []byte) string {
	text := n.Content(src)
	if body := n.ChildByFieldName("body"); body != nil {
		return text[:int(body.StartByte()-n.StartByte())]
	}
	if i := strings.IndexByte(text, '{'); i >= 0 {
		return text[:i]
	}
	return text
}

func swiftFindingCount(findings []QualityFinding) int {
	count := 0
	for _, finding := range findings {
		if strings.HasPrefix(finding.Rule, "swift:") {
			count++
		}
	}
	return count
}

func swiftStatementCount(n *sitter.Node) int {
	if n == nil {
		return 0
	}
	count := 0
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.Type() == "statements" {
			count += swiftStatementCount(child)
			continue
		}
		count++
	}
	return count
}

func swiftTypeMemberCount(n *sitter.Node) int {
	if n == nil {
		return 0
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		body := n.NamedChild(i)
		switch body.Type() {
		case "class_body", "enum_class_body", "protocol_body":
			return int(body.NamedChildCount())
		}
	}
	return 0
}

func swiftInoutCapturedByEscapingClosure(n *sitter.Node, src []byte) bool {
	var inoutNames []string
	escaping := false
	stack := []*sitter.Node{n}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.Type() == "parameter" {
			text := strings.TrimSpace(current.Content(src))
			if strings.Contains(text, "@escaping") {
				escaping = true
			}
			if strings.Contains(text, "inout") {
				before, _, ok := strings.Cut(text, ":")
				if ok {
					fields := strings.Fields(before)
					if len(fields) > 0 {
						name := fields[len(fields)-1]
						if swiftIdentifierRE.MatchString(name) {
							inoutNames = append(inoutNames, name)
						}
					}
				}
			}
		}
		for i := 0; i < int(current.ChildCount()); i++ {
			stack = append(stack, current.Child(i))
		}
	}
	if !escaping || len(inoutNames) == 0 {
		return false
	}
	stack = []*sitter.Node{n}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current != n && current.Type() == "lambda_literal" {
			for _, name := range inoutNames {
				if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(current.Content(src)) {
					return true
				}
			}
			continue
		}
		for i := 0; i < int(current.ChildCount()); i++ {
			stack = append(stack, current.Child(i))
		}
	}
	return false
}

func swiftHasDocumentation(n *sitter.Node, src []byte) bool {
	if p := n.PrevSibling(); p != nil && (p.Type() == "comment" || p.Type() == "multiline_comment") {
		return strings.HasPrefix(strings.TrimSpace(p.Content(src)), "///")
	}
	return false
}

type swiftArgument struct {
	label string
	value string
}

func swiftCallName(n *sitter.Node, src []byte) string {
	callee, suffix := swiftCallParts(n)
	if callee == nil || suffix == nil {
		return ""
	}
	return strings.TrimSpace(callee.Content(src))
}

func swiftCallParts(n *sitter.Node) (callee, suffix *sitter.Node) {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if callee == nil && child.Type() != "call_suffix" {
			callee = child
			continue
		}
		if callee != nil && child.Type() == "call_suffix" {
			return callee, child
		}
	}
	return nil, nil
}

func swiftCallArguments(n *sitter.Node, src []byte) []swiftArgument {
	_, suffix := swiftCallParts(n)
	if suffix == nil {
		return nil
	}
	var args []swiftArgument
	for i := 0; i < int(suffix.NamedChildCount()); i++ {
		child := suffix.NamedChild(i)
		if child.Type() != "value_arguments" {
			continue
		}
		for j := 0; j < int(child.NamedChildCount()); j++ {
			argument := child.NamedChild(j)
			if argument.Type() != "value_argument" {
				continue
			}
			text := strings.TrimSpace(argument.Content(src))
			label, value := "", text
			if first := argument.NamedChild(0); first != nil && first.Type() == "value_argument_label" {
				label = strings.TrimSpace(first.Content(src))
				value = strings.TrimSpace(text[len(first.Content(src)):])
				value = strings.TrimSpace(strings.TrimPrefix(value, ":"))
			}
			args = append(args, swiftArgument{label: label, value: value})
		}
	}
	return args
}

func swiftArgumentsText(args []swiftArgument) string {
	values := make([]string, 0, len(args))
	for _, arg := range args {
		if arg.label != "" {
			values = append(values, arg.label+": "+arg.value)
			continue
		}
		values = append(values, arg.value)
	}
	return strings.Join(values, ", ")
}

func swiftArgumentValue(args []swiftArgument, index int) string {
	if index >= len(args) {
		return ""
	}
	return args[index].value
}

func swiftLabeledArgumentValue(args []swiftArgument, label string) string {
	for _, arg := range args {
		if arg.label == label {
			return arg.value
		}
	}
	return ""
}

func swiftContinuationResumeMissing(text string) bool {
	open := strings.IndexByte(text, '{')
	if open < 0 {
		return true
	}
	body := text[open+1:]
	in := strings.Index(body, " in")
	if in < 0 {
		return true
	}
	name := strings.TrimSpace(body[:in])
	if !swiftIdentifierRE.MatchString(name) {
		return true
	}
	return !regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\.\s*resume\b`).MatchString(body[in+len(" in"):])
}

func swiftClosureCapturesSelf(n *sitter.Node, src []byte) bool {
	stack := []*sitter.Node{n}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current != n && current.Type() == "lambda_literal" {
			text := current.Content(src)
			return strings.Contains(text, "self") && !strings.Contains(text, "[weak self]") && !strings.Contains(text, "[unowned self]")
		}
		for i := 0; i < int(current.ChildCount()); i++ {
			stack = append(stack, current.Child(i))
		}
	}
	return false
}

func swiftLAContextReceiver(name string, n *sitter.Node, src []byte) bool {
	if strings.Contains(name, "LAContext.") {
		return true
	}
	receiver, _, ok := strings.Cut(name, ".evaluatePolicy")
	if !ok || !swiftIdentifierRE.MatchString(receiver) {
		return false
	}
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() != "statements" {
			continue
		}
		for i := 0; i < int(p.NamedChildCount()); i++ {
			statement := p.NamedChild(i)
			if statement.StartByte() >= n.StartByte() {
				break
			}
			text := strings.TrimSpace(statement.Content(src))
			if strings.HasPrefix(text, "let "+receiver+" = LAContext()") || strings.HasPrefix(text, "var "+receiver+" = LAContext()") {
				return true
			}
		}
		return false
	}
	return false
}

func swiftFirstArgumentIsString(args []swiftArgument) bool {
	return swiftStringLiteralRE.MatchString(swiftArgumentValue(args, 0))
}

func swiftRegexLiteral(value string) bool {
	value = strings.TrimSpace(value)
	return swiftStringLiteralRE.MatchString(value) || (strings.HasPrefix(value, "#\"") && strings.HasSuffix(value, "\"#"))
}
func swiftSQLString(s string) bool {
	upper := strings.ToUpper(s)
	return strings.Contains(upper, "SELECT ") || strings.Contains(upper, "INSERT ") || strings.Contains(upper, "UPDATE ") || strings.Contains(upper, "DELETE ")
}

func swiftSQLDynamicArgument(n *sitter.Node, src []byte, args []swiftArgument) bool {
	value := swiftLabeledArgumentValue(args, "sql")
	if value == "" {
		value = swiftLabeledArgumentValue(args, "query")
	}
	if value == "" {
		value = swiftArgumentValue(args, 0)
	}
	if strings.Contains(value, "\\(") && swiftSQLString(value) {
		return true
	}
	if strings.Contains(value, "+") && swiftSQLString(value) {
		return true
	}
	if !swiftIdentifierRE.MatchString(value) {
		return false
	}
	statements := swiftEnclosingStatements(n)
	if statements == nil {
		return false
	}
	for i := 0; i < int(statements.NamedChildCount()); i++ {
		statement := statements.NamedChild(i)
		if statement.StartByte() >= n.StartByte() {
			break
		}
		text := strings.TrimSpace(statement.Content(src))
		if (strings.HasPrefix(text, "let "+value+" =") || strings.HasPrefix(text, "var "+value+" =")) && swiftSQLString(text) && (strings.Contains(text, "\\(") || strings.Contains(text, "+")) {
			return true
		}
	}
	return false
}
func swiftSQLSink(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "query") || strings.Contains(lower, "execute") || strings.Contains(lower, "prepare") || strings.Contains(lower, "sqlite3_exec")
}
func swiftDynamicShellInvocation(n *sitter.Node, src []byte, name string, _ []swiftArgument) bool {
	if name != "Process" {
		return false
	}
	statements := swiftEnclosingStatements(n)
	if statements == nil {
		return false
	}
	processName := swiftDeclaredName(n, src)
	if processName == "" {
		return false
	}
	shell, dynamicCommand := false, false
	for i := 0; i < int(statements.NamedChildCount()); i++ {
		statement := statements.NamedChild(i)
		if statement.StartByte() <= n.StartByte() {
			continue
		}
		text := strings.TrimSpace(statement.Content(src))
		if strings.HasPrefix(text, processName+".executableURL") || strings.HasPrefix(text, processName+".launchPath") {
			shell = swiftShellPath(text)
		}
		if strings.HasPrefix(text, processName+".arguments") && strings.Contains(text, "\"-c\"") {
			dynamicCommand = strings.Contains(text, "\\(") || !strings.HasSuffix(strings.TrimSpace(text), "\"]")
			if !dynamicCommand {
				comma := strings.Index(text, ",")
				if comma >= 0 {
					dynamicCommand = !swiftStringLiteralRE.MatchString(strings.TrimSpace(strings.TrimSuffix(text[comma+1:], "]")))
				}
			}
		}
	}
	return shell && dynamicCommand
}

func swiftEnclosingStatements(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "statements" {
			return p
		}
	}
	return nil
}

func swiftDeclaredName(n *sitter.Node, src []byte) string {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() != "property_declaration" {
			continue
		}
		text := strings.TrimSpace(p.Content(src))
		if !strings.Contains(text, "Process()") {
			return ""
		}
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(text, "let "), "var ")))
		if len(fields) > 0 && swiftIdentifierRE.MatchString(fields[0]) {
			return fields[0]
		}
	}
	return ""
}

func swiftShellPath(text string) bool {
	for _, shell := range []string{"/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/env sh", "/usr/bin/env bash", "/usr/bin/env zsh"} {
		if strings.Contains(text, "\""+shell+"\"") {
			return true
		}
	}
	return false
}
func swiftStaticIVContext(n *sitter.Node, src []byte, args string) bool {
	if !swiftStaticBytes(args) {
		return false
	}
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "property_declaration" || p.Type() == "assignment" {
			left, _, ok := swiftBinarySides(p.Content(src), "=")
			if ok && swiftIVIdentifier(left) {
				return true
			}
		}
		if p.Type() == "value_argument" {
			label, _, ok := strings.Cut(strings.TrimSpace(p.Content(src)), ":")
			if ok && (strings.TrimSpace(label) == "iv" || strings.TrimSpace(label) == "nonce") {
				return true
			}
		}
	}
	return false
}

func swiftStaticBytes(args string) bool {
	compact := strings.ReplaceAll(args, " ", "")
	if strings.Contains(compact, "repeating:") {
		value := strings.TrimPrefix(compact, "repeating:")
		value, _, _ = strings.Cut(value, ",")
		return swiftIntegerRE.MatchString(value) || strings.HasPrefix(value, "0x")
	}
	if swiftStringLiteralRE.MatchString(strings.TrimSpace(args)) {
		return true
	}
	return strings.HasPrefix(compact, "[") && strings.HasSuffix(compact, "]") && !strings.ContainsAny(compact, "\\(")
}

func swiftIVIdentifier(text string) bool {
	text = strings.TrimSpace(text)
	fields := strings.Fields(text)
	if len(fields) > 1 && (fields[0] == "let" || fields[0] == "var") {
		text = strings.Trim(fields[1], ":")
	}
	return text == "iv" || text == "nonce" || strings.HasSuffix(text, "IV") || strings.HasSuffix(text, "Nonce")
}
func swiftUnconditionalTrustCredential(n *sitter.Node, src []byte) bool {
	credential := strings.TrimSpace(n.Content(src))
	for p := n.Parent(); p != nil; p = p.Parent() {
		if !swiftCallableBoundary(p) {
			continue
		}
		stack := []*sitter.Node{p}
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if current != p && swiftCallableBoundary(current) {
				continue
			}
			if current.Type() == "call_expression" && strings.Contains(swiftArgumentsText(swiftCallArguments(current, src)), ".useCredential") && strings.Contains(current.Content(src), credential) {
				return true
			}
			for i := 0; i < int(current.ChildCount()); i++ {
				stack = append(stack, current.Child(i))
			}
		}
		return false
	}
	return false
}
func swiftSecurityContext(n *sitter.Node, src []byte) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() != "assignment" && p.Type() != "property_declaration" {
			continue
		}
		text := p.Content(src)
		if i := strings.IndexByte(text, '='); i >= 0 && swiftSensitiveName(text[:i]) {
			return true
		}
		return false
	}
	return false
}

func swiftLiteralCallSuffix(n *sitter.Node, src []byte) bool {
	text := strings.TrimSpace(n.Content(src))
	return strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") && swiftIntegerRE.MatchString(strings.TrimSpace(text[1:len(text)-1]))
}

func swiftSettingsReceiver(text string) bool {
	start := strings.LastIndexByte(text, '[')
	if start < 0 {
		return false
	}
	receiver := strings.ToLower(strings.TrimSpace(text[:start]))
	return strings.Contains(receiver, "settings") || strings.Contains(receiver, "config")
}

func swiftMatchLocalDeclaration(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	fields := strings.Fields(text)
	if len(fields) >= 2 && (fields[0] == "let" || fields[0] == "var") && len(fields[1]) == 1 && swiftIdentifierRE.MatchString(fields[1]) {
		emit("single-letter-name", n)
	}
	if i := strings.IndexByte(text, '='); i >= 0 && swiftPlausibleKeyMaterial(strings.TrimSpace(text[i+1:])) && swiftSensitiveName(swiftDeclaredPropertyName(text[:i])) {
		emit("hardcoded-key", n)
	}
}

func swiftSensitiveName(name string) bool {
	var normalized strings.Builder
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			normalized.WriteByte(' ')
		}
		if r == '_' || r == '-' {
			normalized.WriteByte(' ')
			continue
		}
		normalized.WriteRune(r)
	}
	return swiftSensitiveNameRE.MatchString(normalized.String())
}

func swiftPlausibleKeyMaterial(value string) bool {
	if !swiftStringLiteralRE.MatchString(value) {
		return false
	}
	value = strings.Trim(strings.TrimSpace(value), "\"")
	if len(value) < 16 || strings.EqualFold(value, "password") || strings.EqualFold(value, "changeme") || strings.Contains(strings.ToLower(value), "example") || strings.Contains(value, "<") {
		return false
	}
	return true
}

func swiftDuplicateSwitchCase(n *sitter.Node, src []byte) bool {
	seen := make(map[string]struct{}, int(n.NamedChildCount()))
	for i := 0; i < int(n.NamedChildCount()); i++ {
		entry := n.NamedChild(i)
		if entry.Type() != "switch_entry" {
			continue
		}
		label := swiftSwitchCaseLabel(entry, src)
		if label == "" {
			continue
		}
		if _, exists := seen[label]; exists {
			return true
		}
		seen[label] = struct{}{}
	}
	return false
}

func swiftSwitchCaseLabel(n *sitter.Node, src []byte) string {
	text := strings.TrimSpace(n.Content(src))
	if !strings.HasPrefix(text, "case ") {
		return ""
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "case "))
	if i := strings.IndexByte(text, ':'); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	if swiftIntegerRE.MatchString(text) || swiftStringLiteralRE.MatchString(text) {
		return text
	}
	return ""
}

func swiftMatchStatements(n *sitter.Node, src []byte, emit func(string, *sitter.Node)) {
	for i := 1; i < int(n.NamedChildCount()); i++ {
		prev, current := n.NamedChild(i-1), n.NamedChild(i)
		if swiftTerminalStatement(prev, src) {
			emit("unreachable-after-return", current)
		}
	}
	if swiftLockAwait(n, src) {
		emit("lock-with-await", n)
	}
}

func swiftTerminalStatement(n *sitter.Node, src []byte) bool {
	text := strings.TrimSpace(n.Content(src))
	return strings.HasPrefix(text, "return") || strings.HasPrefix(text, "throw") || strings.HasPrefix(text, "break") || strings.HasPrefix(text, "continue")
}

func swiftLockAwait(n *sitter.Node, src []byte) bool {
	locked := false
	for i := 0; i < int(n.NamedChildCount()); i++ {
		text := strings.TrimSpace(n.NamedChild(i).Content(src))
		if strings.Contains(text, ".lock()") {
			locked = true
			continue
		}
		if locked && strings.Contains(text, "await ") {
			return true
		}
		if strings.Contains(text, ".unlock()") {
			locked = false
		}
	}
	return false
}

func swiftBridgeHeavyLoop(n *sitter.Node, src []byte) bool {
	text := n.Content(src)
	return (strings.Contains(text, " as NSString") || strings.Contains(text, " as NSData")) && !strings.Contains(text, "autoreleasepool")
}

func swiftMainQueueLoop(n *sitter.Node, src []byte) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() != "call_expression" {
			continue
		}
		return strings.Contains(swiftCallName(p, src), "DispatchQueue.main")
	}
	return false
}

func swiftLoggerCall(name string) bool {
	for _, suffix := range []string{".debug", ".info", ".notice", ".warning", ".error", ".critical", ".log"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func swiftIntegerDivisionArgument(args string) bool {
	left, right, ok := swiftBinarySides(args, "/")
	return ok && swiftIdentifierRE.MatchString(left) && swiftIdentifierRE.MatchString(right)
}

func swiftLocalArrayReceiver(n *sitter.Node, src []byte, call string) bool {
	receiver := strings.TrimSuffix(call, ".contains")
	if !swiftIdentifierRE.MatchString(receiver) {
		return false
	}
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() != "statements" {
			continue
		}
		for i := 0; i < int(p.NamedChildCount()); i++ {
			text := strings.TrimSpace(p.NamedChild(i).Content(src))
			if strings.HasPrefix(text, "let "+receiver+" = [") || strings.HasPrefix(text, "var "+receiver+" = [") || strings.Contains(text, " "+receiver+": [") {
				return true
			}
		}
		for p = p.Parent(); p != nil; p = p.Parent() {
			if p.Type() == "function_declaration" {
				for i := 0; i < int(p.NamedChildCount()); i++ {
					child := p.NamedChild(i)
					if child.Type() == "parameter" && strings.Contains(child.Content(src), receiver) && strings.Contains(child.Content(src), "[") {
						return true
					}
				}
				return false
			}
		}
		return false
	}
	return false
}

func swiftActorHasBlockingCall(n *sitter.Node, src []byte) bool {
	return strings.Contains(n.Content(src), ".wait()") || strings.Contains(n.Content(src), ".lock()") || strings.Contains(n.Content(src), "waitUntilAllOperationsAreFinished")
}

func swiftDeepControlFlow(n *sitter.Node) bool {
	controls := map[string]bool{"if_statement": true, "for_statement": true, "while_statement": true, "repeat_while_statement": true, "switch_statement": true, "guard_statement": true}
	type frame struct {
		n     *sitter.Node
		depth int
	}
	stack := []frame{{n: n}}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.n != n && swiftCallableBoundary(current.n) {
			continue
		}
		depth := current.depth
		if controls[current.n.Type()] {
			depth++
			if depth > 4 {
				return true
			}
		}
		for i := 0; i < int(current.n.ChildCount()); i++ {
			stack = append(stack, frame{n: current.n.Child(i), depth: depth})
		}
	}
	return false
}

func swiftExactReturnType(n *sitter.Node, src []byte, want string) bool {
	result := n.ChildByFieldName("return_type")
	return result != nil && strings.TrimSpace(result.Content(src)) == want
}

func swiftHasExactAnyParameter(n *sitter.Node, src []byte) bool {
	stack := []*sitter.Node{n}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current != n && swiftCallableBoundary(current) {
			continue
		}
		if current.Type() == "parameter" {
			typeNode := current.ChildByFieldName("type")
			if typeNode != nil && strings.TrimSpace(typeNode.Content(src)) == "Any" {
				return true
			}
		}
		for i := 0; i < int(current.ChildCount()); i++ {
			stack = append(stack, current.Child(i))
		}
	}
	return false
}

func swiftAnyObjectCast(n *sitter.Node, src []byte) bool {
	text := n.Content(src)
	i := strings.Index(text, " as!")
	if i < 0 {
		return false
	}
	operand := strings.TrimSpace(text[:i])
	if !swiftIdentifierRE.MatchString(operand) {
		return false
	}
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() != "function_declaration" {
			continue
		}
		for i := 0; i < int(p.NamedChildCount()); i++ {
			parameter := p.NamedChild(i)
			if parameter.Type() == "parameter" && strings.Contains(parameter.Content(src), operand) && strings.Contains(parameter.Content(src), "AnyObject") {
				return true
			}
		}
		return false
	}
	return false
}

func swiftRedundantOptionalBind(n *sitter.Node, src []byte) bool {
	return strings.Contains(n.Content(src), "if let _ =")
}

func swiftConstantCondition(n *sitter.Node, src []byte) bool {
	condition := n.ChildByFieldName("condition")
	if condition == nil {
		return false
	}
	switch strings.TrimSpace(condition.Content(src)) {
	case "true", "false":
		return true
	default:
		return false
	}
}

func swiftStoredSelfMember(n *sitter.Node, src []byte) bool {
	text := strings.TrimSpace(n.Content(src))
	if !strings.HasPrefix(text, "self.") {
		return false
	}
	member := strings.TrimPrefix(strings.Fields(text)[0], "self.")
	member = strings.TrimRight(member, ".")
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() != "class_declaration" && p.Type() != "struct_declaration" {
			continue
		}
		for i := 0; i < int(p.NamedChildCount()); i++ {
			body := p.NamedChild(i)
			if body.Type() != "class_body" {
				continue
			}
			for j := 0; j < int(body.NamedChildCount()); j++ {
				child := body.NamedChild(j)
				if child.Type() == "property_declaration" && swiftDeclaredPropertyName(child.Content(src)) == member && !swiftFunctionShadows(n, src, member) {
					return true
				}
			}
			return false
		}
	}
	return false
}

func swiftDeclaredPropertyName(text string) string {
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(text), "let "), "var ")))
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], ":=")
}

func swiftFunctionShadows(n *sitter.Node, src []byte, name string) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() != "function_declaration" {
			continue
		}
		for i := 0; i < int(p.NamedChildCount()); i++ {
			child := p.NamedChild(i)
			if child.Type() == "parameter" && strings.Contains(child.Content(src), name) {
				return true
			}
		}
		return false
	}
	return false
}
func swiftStandaloneTryExpression(n *sitter.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "statements":
			return true
		case "property_declaration", "assignment", "control_transfer_statement", "value_argument", "call_expression":
			return false
		}
	}
	return false
}
func swiftAssigned(n *sitter.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "assignment", "property_declaration":
			return true
		case "statements", "source_file":
			return false
		}
	}
	return false
}
func swiftCallContext(n *sitter.Node, src []byte, prefix string) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "call_expression" {
			return strings.HasPrefix(swiftCallName(p, src), prefix)
		}
		if p.Type() == "source_file" {
			break
		}
	}
	return false
}
func swiftInsideLoop(n *sitter.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "for_statement", "while_statement", "repeat_while_statement":
			return true
		case "source_file":
			return false
		default:
			if swiftCallableBoundary(p) {
				return false
			}
		}
	}
	return false
}
func swiftCallableBoundary(n *sitter.Node) bool {
	switch n.Type() {
	case "function_declaration", "protocol_function_declaration", "init_declaration", "deinit_declaration", "subscript_declaration", "lambda_literal":
		return true
	default:
		return false
	}
}

func swiftInsideFunction(n *sitter.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if swiftCallableBoundary(p) {
			return true
		}
		if p.Type() == "source_file" {
			break
		}
	}
	return false
}
func swiftGuardElseExits(n *sitter.Node, src []byte) bool {
	for i := int(n.NamedChildCount()) - 1; i >= 0; i-- {
		child := n.NamedChild(i)
		if child.Type() != "statements" {
			continue
		}
		if child.NamedChildCount() == 0 {
			return false
		}
		last := child.NamedChild(int(child.NamedChildCount()) - 1)
		return last.Type() == "control_transfer_statement" && swiftControlFlowExit(last.Content(src))
	}
	return false
}

func swiftControlFlowExit(text string) bool {
	text = strings.TrimSpace(text)
	return strings.HasPrefix(text, "return") || strings.HasPrefix(text, "throw") || strings.HasPrefix(text, "break") || strings.HasPrefix(text, "continue")
}
func swiftBody(text string) string {
	start, end := strings.IndexByte(text, '{'), strings.LastIndexByte(text, '}')
	if start < 0 || end <= start {
		return ""
	}
	return strings.TrimSpace(text[start+1 : end])
}
func swiftBinarySides(text, op string) (string, string, bool) {
	i := strings.Index(text, op)
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+len(op):]), true
}
func swiftEqualitySides(text string) (string, string, bool) {
	if l, r, ok := swiftBinarySides(text, "=="); ok {
		return l, r, true
	}
	return swiftBinarySides(text, "!=")
}
func swiftLiteralGreater(left, right string) bool {
	left = strings.TrimLeft(strings.ReplaceAll(left, "_", ""), "0")
	right = strings.TrimLeft(strings.ReplaceAll(right, "_", ""), "0")
	if len(left) != len(right) {
		return len(left) > len(right)
	}
	return left > right
}
func swiftDuplicateDictionaryKey(text string) bool {
	seen := map[string]bool{}
	for _, part := range strings.Split(text[1:len(text)-1], ",") {
		i := strings.IndexByte(part, ':')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(part[:i])
		if !swiftStringLiteralRE.MatchString(key) {
			continue
		}
		if seen[key] {
			return true
		}
		seen[key] = true
	}
	return false
}
func swiftMagicNumberNode(n *sitter.Node, src []byte) bool {
	if !swiftIntegerRE.MatchString(strings.TrimSpace(n.Content(src))) {
		return false
	}
	p := n.Parent()
	return p != nil && swiftMagicNumberRE.MatchString(p.Content(src))
}
