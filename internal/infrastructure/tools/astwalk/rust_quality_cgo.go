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
	maxRustPerRule    = 20
	maxRustTotal      = 100
	maxRustDepth      = 256
	maxRustNodes      = 20_000
	maxRustWork       = 100_000
	maxRustCandidates = 2_000
)

var (
	rustCommentedCodeRE   = regexp.MustCompile(`^\s*(?:fn|let|struct|enum|impl|use|pub|match|if|for|while)\b`)
	rustMagicNumberRE     = regexp.MustCompile(`(?:==|!=|<=|>=|<|>)\s*([2-9]|[1-9][0-9]+)\b`)
	rustSingleLetterRE    = regexp.MustCompile(`^let\s+(?:mut\s+)?([a-z])\s*=`)
	rustSQLPatternRE      = regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:FROM|INTO|SET|WHERE)`)
	rustSensitiveSecretRE = regexp.MustCompile(`(?i)(?:password|secret|token|api[_-]?key|private[_-]?key)`)
	rustInitCallRE        = regexp.MustCompile(`\binit\s*\(`)
)

func rustFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	findings, _ := rustFindingsLimit(root, src, rel, maxRustTotal)
	return findings
}

func rustFindingsLimit(root *sitter.Node, src []byte, rel string, limit int) ([]QualityFinding, bool) {
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
			if _, ok := rustRuntimeRules[key]; ok {
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
		if nodes >= maxRustNodes || work >= maxRustWork {
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
			rustMatchNode(f.n, src, emit)
			work += len(candidates) - before + 1
			if len(candidates) >= maxRustCandidates {
				truncated = true
				break
			}
		}
		if f.depth >= maxRustDepth {
			if f.n.ChildCount() > 0 {
				truncated = true
			}
			continue
		}
		for i := int(f.n.ChildCount()) - 1; i >= 0; i-- {
			if nodes+len(stack) >= maxRustNodes || work+len(stack) >= maxRustWork {
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
		if len(out) >= limit || perRule[cand.key] >= maxRustPerRule {
			truncated = true
			continue
		}
		ruleDef := rustRuntimeRules[cand.key]
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

func rustMatchNode(n *sitter.Node, src []byte, emit func(string, *sitter.Node)) {
	t := n.Type()
	text := n.Content(src)

	switch t {
	case "call_expression":
		rustMatchCall(n, text, src, emit)
	case "macro_invocation":
		rustMatchMacro(n, text, src, emit)
	case "unsafe_block":
		rustMatchUnsafeBlock(n, text, src, emit)
	case "type_cast_expression":
		rustMatchCast(n, text, emit)
	case "binary_expression":
		rustMatchBinary(n, text, src, emit)
	case "function_item", "function_signature_item":
		rustMatchFunction(n, text, src, emit)
	case "impl_item":
		rustMatchImpl(n, text, src, emit)
	case "struct_item":
		rustMatchStruct(n, text, src, emit)
	case "enum_item":
		rustMatchEnum(n, text, src, emit)
	case "let_declaration":
		rustMatchLet(n, text, src, emit)
	case "if_expression":
		rustMatchIf(n, text, src, emit)
	case "match_expression":
		rustMatchMatch(n, text, src, emit)
	case "closure_expression":
		rustMatchClosure(n, text, src, emit)
	case "line_comment", "block_comment":
		rustMatchComment(n, text, emit)
	case "for_expression", "while_expression", "loop_expression":
		rustMatchLoop(n, text, src, emit)
	case "static_item":
		if strings.Contains(text, "static mut ") {
			emit("unsafe-static-mut-ref", n)
		}
	}
}

func rustMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	callee := rustCallName(n, src)
	args := n.ChildByFieldName("arguments")
	argsText := ""
	if args != nil {
		argsText = args.Content(src)
	}

	if callee == "drop" || callee == "std::mem::drop" || strings.HasSuffix(callee, "::drop") {
		if args != nil && int(args.NamedChildCount()) > 0 {
			firstArg := args.NamedChild(0)
			if firstArg != nil {
				if firstArg.Type() == "reference_expression" || strings.HasPrefix(strings.TrimSpace(firstArg.Content(src)), "&") {
					emit("drop-reference-noop", n)
				}
			}
		}
	}

	if strings.Contains(callee, "transmute") {
		if strings.Contains(argsText, "ptr") || strings.Contains(argsText, "raw") || strings.Contains(text, "*const") || strings.Contains(text, "*mut") || strings.Contains(text, "as_ptr") {
			emit("transmute-ptr-to-ref", n)
		}
		if strings.Contains(text, "&mut") && strings.Contains(text, "transmute") {
			emit("transmute-mut-ref-aliasing", n)
		}
		fn := rustEnclosingFunction(n)
		if fn != nil && !strings.Contains(fn.Content(src), "repr(C)") {
			emit("non-repr-c-transmute", n)
		}
	}
	if strings.HasSuffix(callee, "assume_init") {
		fn := rustEnclosingFunction(n)
		if fn != nil {
			fnText := fn.Content(src)
			if !rustInitCallRE.MatchString(fnText) && !strings.Contains(fnText, "write(") && !strings.Contains(fnText, "copy") {
				emit("uninit-buffer-exposure", n)
			}
		}
	}
	if strings.Contains(callee, "slice::from_raw_parts") || callee == "from_raw_parts" || callee == "from_raw_parts_mut" {
		if !rustHasNullCheck(n, src) {
			emit("slice-from-raw-parts-null", n)
		}
	}
	if strings.Contains(callee, "copy_nonoverlapping") {
		emit("ptr-copy-overlap-hazard", n)
	}
	if strings.HasSuffix(callee, ".add") || strings.HasSuffix(callee, ".offset") || strings.HasSuffix(callee, ".sub") {
		if !rustHasBoundsCheck(n, src) {
			emit("raw-pointer-arithmetic-oob", n)
		}
	}
	if strings.Contains(callee, "Box::into_raw") || callee == "into_raw" {
		if rustIsDiscarded(n, src) {
			emit("leaked-raw-box", n)
		}
	}
	if strings.HasSuffix(callee, "expect") {
		if strings.Contains(argsText, "\"\"") || strings.Contains(argsText, "\" \"") {
			emit("expect-empty-message", n)
		}
	}
	if strings.Contains(callee, "libc::free") || callee == "free" {
		emit("ffi-freed-c-pointer", n)
	}
	if strings.HasSuffix(callee, "unbounded_channel") || strings.HasSuffix(callee, "channel::unbounded") {
		emit("unbounded-channel-send", n)
	}
	if (strings.Contains(callee, "thread::spawn") || callee == "spawn") && rustInLoop(n) {
		emit("thread-spawn-in-loop", n)
	}
	if strings.HasSuffix(callee, ".wait") && !rustInWhileLoop(n) {
		emit("condvar-wait-no-predicate", n)
	}
	if strings.Contains(text, "Aes128Ecb") || strings.Contains(text, "Aes256Ecb") || strings.Contains(callee, "Ecb") {
		emit("insecure-cipher-ecb", n)
	}
	if (strings.Contains(callee, "rand::random") || strings.Contains(callee, "thread_rng") || strings.Contains(callee, "rng")) &&
		rustSensitiveSecretRE.MatchString(text) {
		emit("insecure-prng-security", n)
	}
	if strings.Contains(callee, "Nonce::from_slice") {
		if strings.Contains(argsText, "b\"") || strings.Contains(argsText, "&[") {
			emit("static-nonce-reuse", n)
		}
	}
	if strings.Contains(callee, "Md5::digest") || strings.Contains(callee, "Sha1::digest") || strings.Contains(callee, "md5::") || strings.Contains(callee, "sha1::") {
		emit("deprecated-hash-md5", n)
	}
	if strings.Contains(callee, "RsaPrivateKey::new") || strings.Contains(callee, "Rsa::generate") {
		if args != nil {
			for i := 0; i < int(args.NamedChildCount()); i++ {
				argNode := args.NamedChild(i)
				if argNode.Type() == "integer_literal" {
					if val, err := strconv.Atoi(strings.TrimSpace(argNode.Content(src))); err == nil && val < 2048 {
						emit("weak-rsa-key-size", n)
						break
					}
				}
			}
		}
	}
	if strings.Contains(callee, "Regex::new") {
		if !strings.Contains(argsText, "\"") || strings.Contains(argsText, "format!") {
			emit("regex-dynamic-compilation", n)
		}
	}
	if strings.Contains(callee, "render_str") || strings.Contains(callee, "render_template") {
		if !strings.Contains(argsText, "\"") {
			emit("server-side-template-injection", n)
		}
	}
	if strings.HasSuffix(callee, "extract") && strings.Contains(text, "zip") {
		fn := rustEnclosingFunction(n)
		if fn != nil && !strings.Contains(fn.Content(src), "enclosed_name") {
			emit("unrestricted-zip-extract", n)
		}
	}
	if strings.Contains(callee, "eval") {
		emit("eval-dynamic-expression", n)
	}
	if strings.Contains(callee, "char::from_u32_unchecked") {
		emit("char-from-u32-unchecked", n)
	}
	if strings.Contains(callee, "File::create") && strings.Contains(argsText, "/tmp/") {
		emit("tempfile-insecure-path", n)
	}
	if strings.Contains(callee, "TcpStream::connect") {
		fn := rustEnclosingFunction(n)
		if fn != nil && !strings.Contains(fn.Content(src), "set_read_timeout") {
			emit("socket-missing-timeout", n)
		}
	}
	if strings.HasSuffix(callee, ".spawn") {
		fn := rustEnclosingFunction(n)
		if fn != nil {
			fnText := fn.Content(src)
			if !strings.Contains(fnText, ".wait(") && !strings.Contains(fnText, ".wait()") && !strings.Contains(fnText, ".wait_with_output") && !strings.Contains(fnText, ".status") {
				emit("child-process-not-waited", n)
			}
		}
	}
	if strings.HasSuffix(callee, ".reserve") {
		if !rustHasBoundsCheck(n, src) {
			emit("unbounded-vec-reserve", n)
		}
	}
	if strings.Contains(callee, "Box::new") {
		if args != nil && int(args.NamedChildCount()) == 1 {
			arg := args.NamedChild(0)
			if arg != nil {
				tName := arg.Type()
				if tName == "integer_literal" || tName == "float_literal" || tName == "boolean_literal" || tName == "char_literal" {
					emit("unneeded-box-sized", n)
				}
			}
		}
	}
	if strings.HasSuffix(callee, ".clone") && rustInLoop(n) {
		emit("clone-in-hot-loop", n)
	}
	if strings.HasSuffix(callee, ".join") {
		fn := rustEnclosingFunction(n)
		if fn != nil {
			fnText := fn.Content(src)
			if !strings.Contains(fnText, "file_name") && !strings.Contains(fnText, "sanitize") && !strings.Contains(fnText, "canonicalize") && !strings.Contains(fnText, "clean") {
				emit("path-traversal-join", n)
			}
		}
	}
	if (strings.HasSuffix(callee, "borrow") || strings.HasSuffix(callee, "borrow_mut")) && rustInBlockWithAwait(n, src) {
		emit("refcell-borrow-across-await", n)
	}
	if (strings.HasSuffix(callee, ".store") || strings.HasSuffix(callee, ".load")) && strings.Contains(argsText, "Ordering::Relaxed") {
		emit("atomic-relaxed-ordering-sync", n)
	}
	if strings.Contains(callee, "lock") && rustInBlockWithAwait(n, src) {
		emit("lock-held-across-await", n)
	}
	if strings.HasSuffix(callee, "unwrap") && rustInDropImpl(n, src) {
		emit("panic-in-drop", n)
	}
	if strings.Contains(text, "Command::new") && (strings.Contains(text, "\"sh\"") || strings.Contains(text, "\"bash\"") || strings.Contains(text, "\"cmd\"")) {
		if strings.Contains(text, "format!") || strings.Contains(text, "user_") || strings.Contains(text, "arg") || strings.Contains(text, "-c") {
			emit("command-injection-sh", n)
		}
	}
	if strings.Contains(text, "Algorithm::None") {
		emit("jwt-insecure-none-algo", n)
	}
	if strings.Contains(text, ".as_ptr()") && (strings.Contains(text, "*const") || strings.Contains(text, "c_char")) && !strings.Contains(text, "\\0") {
		emit("ffi-c-string-missing-nul", n)
	}
}

func rustInBlockWithAwait(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "block" {
			return strings.Contains(curr.Content(src), ".await")
		}
		if curr.Type() == "function_item" || curr.Type() == "closure_expression" {
			break
		}
		curr = curr.Parent()
	}
	return false
}

func rustMatchMacro(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	args := n.ChildByFieldName("arguments")
	argsText := ""
	if args != nil {
		argsText = args.Content(src)
	}

	if strings.HasPrefix(text, "panic!(") || strings.HasPrefix(text, "unreachable!(") || strings.HasPrefix(text, "todo!(") {
		if rustInFFIFunction(n, src) {
			emit("panic-in-ffi-boundary", n)
		}
		if rustInDropImpl(n, src) {
			emit("panic-in-drop", n)
		}
	}
	if strings.HasPrefix(text, "format!(") {
		if rustSQLPatternRE.MatchString(argsText) {
			emit("sql-string-formatting", n)
		}
		if strings.Contains(argsText, "uid=") || strings.Contains(argsText, "cn=") {
			emit("ldap-injection-filter", n)
		}
		if strings.Contains(argsText, "//") || strings.Contains(argsText, "[@") {
			emit("xpath-injection-query", n)
		}
	}
	if strings.Contains(text, "Command::new") || strings.Contains(text, "Command::new(\"sh\")") || strings.Contains(text, "Command::new(\"bash\")") || strings.Contains(text, "Command::new(\"cmd\")") {
		if strings.Contains(text, "format!") || strings.Contains(argsText, "arg") || !strings.Contains(argsText, "\"") {
			emit("command-injection-sh", n)
		}
	}
}

func rustMatchUnsafeBlock(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "*ptr") || strings.Contains(text, "*raw") {
		if !rustHasNullCheck(n, src) {
			emit("raw-ptr-deref-no-null-check", n)
		}
	}
	if strings.Contains(text, "read_unaligned") || strings.Contains(text, "align_to") || (strings.Contains(text, "*const u8") && strings.Contains(text, "*const u64")) {
		emit("unaligned-raw-ptr-read", n)
	}
	if rustInFFIFunction(n, src) && (strings.Contains(text, "*ptr") || strings.Contains(text, "*raw")) && !rustHasNullCheck(n, src) {
		emit("ffi-null-ptr-unchecked", n)
	}
	if rustCountStatements(n) >= 4 {
		emit("unsafe-block-scope", n)
	}
}

func rustMatchCast(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "as u16") || strings.Contains(text, "as u8") || strings.Contains(text, "as i8") || strings.Contains(text, "as i16") {
		emit("lossy-integer-cast", n)
	}
	if strings.Contains(text, "as usize") || strings.Contains(text, "as u32") || strings.Contains(text, "as u64") {
		if strings.Contains(text, "signed") || strings.Contains(text, "i32") || strings.Contains(text, "i64") {
			emit("signed-unsigned-cast-hazard", n)
		}
	}
	if (strings.Contains(text, "as u32") || strings.Contains(text, "as i32")) && (strings.Contains(text, "ptr") || strings.Contains(text, "*const") || strings.Contains(text, "*mut")) {
		emit("pointer-to-integer-cast", n)
	}
}

func rustMatchBinary(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "== f64::NAN") || strings.Contains(text, "== f32::NAN") || strings.Contains(text, "!= f64::NAN") || strings.Contains(text, "!= f32::NAN") {
		emit("float-nan-comparison", n)
	}
	if (strings.Contains(text, "token") || strings.Contains(text, "secret") || strings.Contains(text, "hash") || strings.Contains(text, "key")) &&
		(strings.Contains(text, "==") || strings.Contains(text, "!=")) {
		emit("timing-attack-memcmp", n)
	}
	if strings.Contains(text, "<<") || strings.Contains(text, ">>") {
		if (strings.Contains(text, "32") || strings.Contains(text, "64") || strings.Contains(text, "shift")) && !rustHasBoundsCheck(n, src) && !strings.Contains(text, "< 32") && !strings.Contains(text, "< 64") {
			emit("bitshift-oversized", n)
		}
	}
	if rustMagicNumberRE.MatchString(text) {
		emit("magic-number-condition", n)
	}
}

func rustMatchFunction(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(text, "pub unsafe fn") || strings.HasPrefix(text, "unsafe fn") {
		if !rustHasSafetyDoc(n, src) {
			emit("unsafe-fn-without-doc", n)
		}
	}
	if strings.Contains(text, "extern \"C\" fn") || strings.Contains(text, "extern \"C\" {") {
		if strings.Contains(text, "panic!") || strings.Contains(text, "unwrap()") {
			emit("panic-in-ffi-boundary", n)
		}
		if (strings.Contains(text, "Handle") || strings.Contains(text, "Struct") || strings.Contains(text, "Opaque")) && !strings.Contains(text, "*mut") && !strings.Contains(text, "*const") && !strings.Contains(text, "&") {
			emit("ffi-opaque-struct-by-value", n)
		}
		if strings.Contains(text, ".as_ptr()") && (strings.Contains(text, "*const") || strings.Contains(text, "c_char")) {
			emit("ffi-c-string-missing-nul", n)
		}
	}
	if strings.Contains(text, "encode_utf16().collect()") && !strings.Contains(text, "chain") {
		emit("ffi-wide-string-unterminated", n)
	}
	if rustCountStatements(n) > 50 {
		emit("long-function-statements", n)
	}
	if rustParameterCount(n) > 7 {
		emit("excessive-parameters", n)
	}
	if rustMaxControlNesting(n) > 4 {
		emit("deep-control-nesting", n)
	}
	if strings.HasPrefix(text, "pub fn is_empty") || strings.HasPrefix(text, "pub fn len") || strings.HasPrefix(text, "pub fn is_valid") {
		if !rustHasMustUse(n, src) {
			emit("missing-must-use", n)
		}
	}
	if strings.HasPrefix(text, "pub fn ") && !rustHasDocComment(n, src) {
		emit("public-api-undocumented", n)
	}
}

func rustMatchImpl(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(text, "unsafe impl") && (strings.Contains(text, "Send for") || strings.Contains(text, "Sync for")) {
		emit("unsafe-impl-send-sync", n)
	}
	if strings.Contains(text, "Display for") {
		fn := rustEnclosingFunction(n)
		if fn == nil {
			if !strings.Contains(string(src), "Debug") {
				emit("display-missing-debug", n)
			}
		}
	}
}

func rustMatchStruct(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if (strings.HasPrefix(text, "pub struct ") || strings.HasPrefix(text, "struct ")) && (strings.Contains(text, "Header") || strings.Contains(text, "CStruct") || strings.Contains(text, "FFI")) {
		if !rustHasReprC(n, src) {
			emit("ffi-missing-repr-c", n)
		}
	}
}

func rustMatchEnum(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "Error") && !strings.Contains(string(src), "thiserror") && !strings.Contains(string(src), "std::error") {
		emit("custom-error-no-std-trait", n)
	}
	if strings.Contains(text, "[u8; ") && !strings.Contains(text, "Box<") {
		// Check variant size
		if strings.Contains(text, "1024") || strings.Contains(text, "2048") || strings.Contains(text, "4096") || strings.Contains(text, "512") {
			emit("large-enum-variant-size", n)
		}
	}
}

func rustMatchLet(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(strings.TrimSpace(text), "let _ =") {
		emit("swallowed-error-let-underscore", n)
	}
	if strings.Contains(text, "Cell::new") || strings.Contains(text, "RefCell::new") {
		emit("interior-mutability-shared", n)
	}
	if strings.Contains(text, "Ordering::Relaxed") {
		emit("atomic-relaxed-ordering-sync", n)
	}
	if rustSensitiveSecretRE.MatchString(text) && strings.Contains(text, "b\"") {
		emit("hardcoded-secret-bytes", n)
	}
	if rustSingleLetterRE.MatchString(text) && !rustInLoop(n) {
		emit("single-letter-variable-name", n)
	}
}

func rustMatchIf(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	cons := n.ChildByFieldName("consequence")
	alt := n.ChildByFieldName("alternative")
	if cons != nil && alt == nil {
		for i := 0; i < int(cons.NamedChildCount()); i++ {
			child := cons.NamedChild(i)
			if child.Type() == "if_expression" && child.ChildByFieldName("alternative") == nil {
				emit("collapsible-if-statements", n)
				break
			}
		}
	}
}

func rustMatchMatch(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	body := n.ChildByFieldName("body")
	if body != nil && body.NamedChildCount() == 1 {
		emit("match-single-binding", n)
	}
}

func rustMatchClosure(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if rustIsRedundantClosure(n, src) {
		emit("redundant-closure-call", n)
	}
}

func rustIsRedundantClosure(n *sitter.Node, src []byte) bool {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if n.NamedChild(i).Type() == "closure_parameters" {
				params = n.NamedChild(i)
				break
			}
		}
	}
	if params == nil || params.NamedChildCount() == 0 {
		return false
	}
	var paramNames []string
	for i := 0; i < int(params.NamedChildCount()); i++ {
		p := params.NamedChild(i)
		pName := strings.TrimSpace(p.Content(src))
		if pName == "" || strings.Contains(pName, " ") {
			return false
		}
		paramNames = append(paramNames, pName)
	}

	body := n.ChildByFieldName("body")
	if body == nil && n.NamedChildCount() > 0 {
		body = n.NamedChild(int(n.NamedChildCount()) - 1)
	}
	if body == nil {
		return false
	}
	call := body
	if body.Type() == "block" {
		if body.NamedChildCount() != 1 {
			return false
		}
		call = body.NamedChild(0)
		if call.Type() == "expression_statement" && call.NamedChildCount() == 1 {
			call = call.NamedChild(0)
		}
	}
	if call.Type() != "call_expression" {
		return false
	}
	args := call.ChildByFieldName("arguments")
	if args == nil || int(args.NamedChildCount()) != len(paramNames) {
		return false
	}
	for i := 0; i < len(paramNames); i++ {
		arg := args.NamedChild(i)
		if arg.Type() != "identifier" || strings.TrimSpace(arg.Content(src)) != paramNames[i] {
			return false
		}
	}
	return true
}

func rustMatchComment(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	clean := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(text, "//"), "/*"))
	upper := strings.ToUpper(clean)
	if strings.Contains(upper, "TODO:") || strings.Contains(upper, "FIXME:") {
		emit("todo-comment-untracked", n)
	}
	if rustCommentedCodeRE.MatchString(clean) {
		emit("commented-out-code", n)
	}
}

func rustMatchLoop(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if (strings.Contains(text, "file.read(") || strings.Contains(text, "file.write(")) && !strings.Contains(text, "BufReader") && !strings.Contains(text, "BufWriter") {
		emit("file-unbuffered-io", n)
	}
}

func rustHasBoundsCheck(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_expression" {
			cond := curr.ChildByFieldName("condition")
			if cond != nil && (strings.Contains(cond.Content(src), "<") || strings.Contains(cond.Content(src), "<=")) {
				return true
			}
		}
		curr = curr.Parent()
	}
	return false
}

// Helpers

func rustCallName(n *sitter.Node, src []byte) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	return strings.TrimSpace(fn.Content(src))
}

func rustEnclosingFunction(n *sitter.Node) *sitter.Node {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "function_item" {
			return curr
		}
		curr = curr.Parent()
	}
	return nil
}

func rustInLoop(n *sitter.Node) bool {
	curr := n.Parent()
	for curr != nil {
		switch curr.Type() {
		case "for_expression", "while_expression", "loop_expression":
			return true
		}
		curr = curr.Parent()
	}
	return false
}

func rustInWhileLoop(n *sitter.Node) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "while_expression" {
			return true
		}
		curr = curr.Parent()
	}
	return false
}

func rustInFFIFunction(n *sitter.Node, src []byte) bool {
	fn := rustEnclosingFunction(n)
	if fn != nil {
		return strings.Contains(fn.Content(src), "extern \"C\"")
	}
	return false
}

func rustInDropImpl(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "impl_item" {
			return strings.Contains(curr.Content(src), "Drop for")
		}
		curr = curr.Parent()
	}
	return false
}

func rustHasDocComment(n *sitter.Node, src []byte) bool {
	prev := n.PrevSibling()
	if prev != nil && (prev.Type() == "line_comment" || prev.Type() == "block_comment") {
		txt := strings.TrimSpace(prev.Content(src))
		return strings.HasPrefix(txt, "///") || strings.HasPrefix(txt, "/**")
	}
	return false
}

func rustHasSafetyDoc(n *sitter.Node, src []byte) bool {
	prev := n.PrevSibling()
	if prev != nil && (prev.Type() == "line_comment" || prev.Type() == "block_comment") {
		txt := prev.Content(src)
		if strings.Contains(txt, "# Safety") || strings.Contains(txt, "Safety:") {
			return true
		}
	}
	return false
}

func rustHasReprC(n *sitter.Node, src []byte) bool {
	prev := n.PrevSibling()
	for prev != nil && (prev.Type() == "attribute_item" || prev.Type() == "line_comment" || prev.Type() == "block_comment") {
		if prev.Type() == "attribute_item" && (strings.Contains(prev.Content(src), "repr(C)") || strings.Contains(prev.Content(src), "repr(transparent)")) {
			return true
		}
		prev = prev.PrevSibling()
	}
	return false
}

func rustHasMustUse(n *sitter.Node, src []byte) bool {
	prev := n.PrevSibling()
	for prev != nil && (prev.Type() == "attribute_item" || prev.Type() == "line_comment" || prev.Type() == "block_comment") {
		if prev.Type() == "attribute_item" && strings.Contains(prev.Content(src), "must_use") {
			return true
		}
		prev = prev.PrevSibling()
	}
	return false
}

func rustHasNullCheck(n *sitter.Node, src []byte) bool {
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "if_expression" || curr.Type() == "match_expression" {
			txt := curr.Content(src)
			if strings.Contains(txt, "is_null") || strings.Contains(txt, "as_ref") || strings.Contains(txt, "!= null") {
				return true
			}
		}
		if curr.Type() == "function_item" {
			break
		}
		curr = curr.Parent()
	}
	return false
}

func rustIsDiscarded(n *sitter.Node, src []byte) bool {
	parent := n.Parent()
	if parent != nil {
		if parent.Type() == "let_declaration" && strings.HasPrefix(strings.TrimSpace(parent.Content(src)), "let _") {
			return true
		}
		if parent.Type() == "expression_statement" {
			return true
		}
	}
	return false
}

func rustCountStatements(n *sitter.Node) int {
	body := n.ChildByFieldName("body")
	if body == nil {
		return int(n.NamedChildCount())
	}
	return int(body.NamedChildCount())
}

func rustParameterCount(fn *sitter.Node) int {
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return 0
	}
	return int(params.NamedChildCount())
}

func rustMaxControlNesting(n *sitter.Node) int {
	controlTypes := map[string]bool{
		"if_expression": true, "for_expression": true, "while_expression": true, "loop_expression": true, "match_expression": true,
	}
	best := 0
	for i := 0; i < int(n.ChildCount()); i++ {
		if d := rustMaxControlNesting(n.Child(i)); d > best {
			best = d
		}
	}
	if controlTypes[n.Type()] {
		return best + 1
	}
	return best
}
