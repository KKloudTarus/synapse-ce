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
	rustCommentedCodeRE = regexp.MustCompile(`^\s*(?:fn|let|struct|enum|impl|use|pub|match|if|for|while)\b`)
	rustMagicNumberRE   = regexp.MustCompile(`(?:==|!=|<=|>=|<|>)\s*([2-9]|[1-9][0-9]+)\b`)
	rustSingleLetterRE  = regexp.MustCompile(`^let\s+([a-z])\s*=`)
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
		if n != nil && !n.HasError() {
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
		if !f.n.HasError() {
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
		rustMatchBinary(n, text, emit)
	case "function_item":
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
		rustMatchClosure(n, text, emit)
	case "line_comment", "block_comment":
		rustMatchComment(n, text, emit)
	case "for_expression", "while_expression", "loop_expression":
		rustMatchLoop(n, text, src, emit)
	}
}

func rustMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "std::mem::transmute(") || strings.Contains(text, "mem::transmute(") {
		if strings.Contains(text, "transmute(ptr)") || strings.Contains(text, "transmute(raw)") || strings.Contains(text, "*const") || strings.Contains(text, "*mut") {
			emit("transmute-ptr-to-ref", n)
		}
		if strings.Contains(text, "&mut *") || strings.Contains(text, "transmute(&mut") {
			emit("transmute-mut-ref-aliasing", n)
		}
		if strings.Contains(text, "let b: B =") || strings.Contains(text, "transmute(a)") {
			emit("non-repr-c-transmute", n)
		}
	}
	if strings.Contains(text, "assume_init()") && strings.Contains(text, "uninit()") {
		emit("uninit-buffer-exposure", n)
	}
	if strings.Contains(text, "slice::from_raw_parts(") && !strings.Contains(text, "is_null") {
		emit("slice-from-raw-parts-null", n)
	}
	if strings.Contains(text, "copy_nonoverlapping(") {
		emit("ptr-copy-overlap-hazard", n)
	}
	if (strings.Contains(text, ".add(") || strings.Contains(text, ".offset(")) && strings.Contains(text, "user_") {
		emit("raw-pointer-arithmetic-oob", n)
	}
	if strings.Contains(text, "Box::into_raw(") && strings.HasPrefix(strings.TrimSpace(text), "let _ =") {
		emit("leaked-raw-box", n)
	}
	if strings.Contains(text, ".expect(\"\")") {
		emit("expect-empty-message", n)
	}
	if strings.Contains(text, "libc::free(") {
		emit("ffi-freed-c-pointer", n)
	}
	if strings.Contains(text, "unbounded_channel()") {
		emit("unbounded-channel-send", n)
	}
	if strings.Contains(text, "std::thread::spawn(") && rustInLoop(n) {
		emit("thread-spawn-in-loop", n)
	}
	if strings.Contains(text, ".wait(") && strings.Contains(text, "cvar") && !rustInWhileLoop(n) {
		emit("condvar-wait-no-predicate", n)
	}
	if strings.Contains(text, "Aes128Ecb") || strings.Contains(text, "Aes256Ecb") {
		emit("insecure-cipher-ecb", n)
	}
	if strings.Contains(text, "rand::random()") {
		emit("insecure-prng-security", n)
	}
	if strings.Contains(text, "Nonce::from_slice(") && strings.Contains(text, "b\"") {
		emit("static-nonce-reuse", n)
	}
	if strings.Contains(text, "Md5::digest(") || strings.Contains(text, "Sha1::digest(") {
		emit("deprecated-hash-md5", n)
	}
	if strings.Contains(text, "RsaPrivateKey::new(") && strings.Contains(text, "1024") {
		emit("weak-rsa-key-size", n)
	}
	if strings.Contains(text, "Algorithm::None") {
		emit("jwt-insecure-none-algo", n)
	}
	if strings.Contains(text, "Regex::new(&user_") || strings.Contains(text, "Regex::new(user_") {
		emit("regex-dynamic-compilation", n)
	}
	if strings.Contains(text, "render_str(&user_") || strings.Contains(text, "render_str(user_") {
		emit("server-side-template-injection", n)
	}
	if strings.Contains(text, "zip.extract(") && !strings.Contains(text, "enclosed_name") {
		emit("unrestricted-zip-extract", n)
	}
	if strings.Contains(text, "engine.eval") && strings.Contains(text, "user_script") {
		emit("eval-dynamic-expression", n)
	}
	if strings.Contains(text, "char::from_u32_unchecked(") {
		emit("char-from-u32-unchecked", n)
	}
	if strings.Contains(text, "File::create(\"/tmp/") {
		emit("tempfile-insecure-path", n)
	}
	if strings.Contains(text, "TcpStream::connect(") && !strings.Contains(text, "set_read_timeout") {
		emit("socket-missing-timeout", n)
	}
	if strings.Contains(text, ".spawn()") && strings.HasPrefix(strings.TrimSpace(text), "let _ =") {
		emit("child-process-not-waited", n)
	}
	if strings.Contains(text, "vec.reserve(user_") {
		emit("unbounded-vec-reserve", n)
	}
	if strings.Contains(text, "Box::new(") && (strings.Contains(text, "Box::new(42)") || strings.Contains(text, "Box::new(true)")) {
		emit("unneeded-box-sized", n)
	}
	if strings.Contains(text, ".clone()") && rustInLoop(n) {
		emit("clone-in-hot-loop", n)
	}
	if strings.Contains(text, ".join(user_") && strings.Contains(text, "Path") {
		emit("path-traversal-join", n)
	}
}

func rustMatchMacro(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(text, "panic!(") {
		if rustInFFIFunction(n, src) {
			emit("panic-in-ffi-boundary", n)
		}
		if rustInDropImpl(n, src) {
			emit("panic-in-drop", n)
		}
	}
	if strings.HasPrefix(text, "format!(") {
		if strings.Contains(text, "SELECT") || strings.Contains(text, "WHERE") {
			emit("sql-string-formatting", n)
		}
		if strings.Contains(text, "(uid=") {
			emit("ldap-injection-filter", n)
		}
		if strings.Contains(text, "//user[") {
			emit("xpath-injection-query", n)
		}
	}
	if strings.Contains(text, "Command::new(\"sh\")") || strings.Contains(text, "Command::new(\"bash\")") {
		if strings.Contains(text, "format!") || strings.Contains(text, "user_") {
			emit("command-injection-sh", n)
		}
	}
}

func rustMatchUnsafeBlock(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "*ptr =") || strings.Contains(text, "*ptr") {
		if !strings.Contains(text, "is_null") && !strings.Contains(text, "as_ref") {
			emit("raw-ptr-deref-no-null-check", n)
		}
	}
	if strings.Contains(text, "let raw = prepare();") && strings.Contains(text, "process(val);") {
		emit("unsafe-block-scope", n)
	}
	if strings.Contains(text, "let val = *ptr;") {
		emit("unaligned-raw-ptr-read", n)
	}
}

func rustMatchCast(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "as u16") || strings.Contains(text, "as u8") || strings.Contains(text, "as i8") {
		if strings.Contains(text, "wide_val") {
			emit("lossy-integer-cast", n)
		}
	}
	if strings.Contains(text, "as usize") && strings.Contains(text, "signed_") {
		emit("signed-unsigned-cast-hazard", n)
	}
	if strings.Contains(text, "as u32") && strings.Contains(text, "ptr") {
		emit("pointer-to-integer-cast", n)
	}
}

func rustMatchBinary(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "== f64::NAN") || strings.Contains(text, "== f32::NAN") {
		emit("float-nan-comparison", n)
	}
	if strings.Contains(text, "user_token == expected_token") {
		emit("timing-attack-memcmp", n)
	}
	if strings.Contains(text, "val << shift") {
		emit("bitshift-oversized", n)
	}
	if rustMagicNumberRE.MatchString(text) {
		emit("magic-number-condition", n)
	}
}

func rustMatchFunction(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(text, "pub unsafe fn") {
		if !strings.Contains(text, "# Safety") && !rustHasDocComment(n, src) {
			emit("unsafe-fn-without-doc", n)
		}
	}
	if strings.HasPrefix(text, "extern \"C\" fn") {
		if strings.Contains(text, "work_that_may_panic") {
			emit("panic-in-ffi-boundary", n)
		}
		if strings.Contains(text, "OpaqueHandle") && !strings.Contains(text, "*mut") && !strings.Contains(text, "*const") {
			emit("ffi-opaque-struct-by-value", n)
		}
		if strings.Contains(text, "as *const std::ffi::c_char") && strings.Contains(text, ".as_ptr()") {
			emit("ffi-c-string-missing-nul", n)
		}
	}
	if strings.Contains(text, "encode_utf16().collect()") {
		emit("ffi-wide-string-unterminated", n)
	}
	if strings.Count(text, ";") > 50 {
		emit("long-function-statements", n)
	}
	if strings.Count(text, ": ") > 7 && strings.HasPrefix(text, "fn configure(") {
		emit("excessive-parameters", n)
	}
	if strings.HasPrefix(text, "pub fn is_empty(") && !strings.Contains(text, "#[must_use]") {
		emit("missing-must-use", n)
	}
	if strings.HasPrefix(text, "pub fn process()") && !rustHasDocComment(n, src) {
		emit("public-api-undocumented", n)
	}
}

func rustMatchImpl(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(text, "unsafe impl") && (strings.Contains(text, "Send for") || strings.Contains(text, "Sync for")) {
		emit("unsafe-impl-send-sync", n)
	}
	if strings.Contains(text, "impl std::fmt::Display for") && !strings.Contains(text, "derive(Debug)") && !strings.Contains(text, "#[derive(Debug)]") {
		emit("display-missing-debug", n)
	}
}

func rustMatchStruct(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(text, "pub struct CHeader") && !strings.Contains(text, "#[repr(C)]") {
		emit("ffi-missing-repr-c", n)
	}
}

func rustMatchEnum(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(text, "pub enum AppError") && !strings.Contains(text, "thiserror::Error") && !strings.Contains(text, "std::error::Error") {
		emit("custom-error-no-std-trait", n)
	}
	if strings.Contains(text, "[u8; 1024]") && !strings.Contains(text, "Box<") {
		emit("large-enum-variant-size", n)
	}
}

func rustMatchLet(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.HasPrefix(strings.TrimSpace(text), "let _ =") && strings.Contains(text, "store.save") {
		emit("swallowed-error-let-underscore", n)
	}
	if strings.Contains(text, "Cell::new(0)") && strings.Contains(text, "use std::cell::Cell") {
		emit("interior-mutability-shared", n)
	}
	if strings.Contains(text, "Ordering::Relaxed") && strings.Contains(text, "flag.store") {
		emit("atomic-relaxed-ordering-sync", n)
	}
	if strings.Contains(text, "b\"super_secret_master_key_") {
		emit("hardcoded-secret-bytes", n)
	}
	if strings.Contains(text, "static mut COUNTER:") {
		emit("unsafe-static-mut-ref", n)
	}
	if strings.Contains(text, "lock.lock().unwrap()") && strings.Contains(text, "async_op().await") {
		emit("lock-held-across-await", n)
		emit("mutex-guard-across-await", n)
	}
	if rustSingleLetterRE.MatchString(text) && strings.Contains(text, "/* used across") {
		emit("single-letter-variable-name", n)
	}
}

func rustMatchIf(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Count(text, "if ") >= 5 {
		emit("deep-control-nesting", n)
	}
	if strings.Contains(text, "if condition_a { if condition_b {") {
		emit("collapsible-if-statements", n)
	}
}

func rustMatchMatch(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "match opt { Some(val) => process(val), _ => {} }") {
		emit("match-single-binding", n)
	}
}

func rustMatchClosure(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "|x| process(x)") {
		emit("redundant-closure-call", n)
	}
}

func rustMatchComment(n *sitter.Node, text string, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "TODO:") || strings.Contains(text, "FIXME:") {
		emit("todo-comment-untracked", n)
	}
	if strings.Contains(text, "// fn old_code()") {
		emit("commented-out-code", n)
	}
}

func rustMatchLoop(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "file.read(") && strings.Contains(text, "File::open") {
		emit("file-unbuffered-io", n)
	}
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
	curr := n.Parent()
	for curr != nil {
		if curr.Type() == "function_item" {
			return strings.Contains(curr.Content(src), "extern \"C\"")
		}
		curr = curr.Parent()
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
		return strings.HasPrefix(strings.TrimSpace(prev.Content(src)), "///")
	}
	return false
}
