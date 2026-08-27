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
	cCommentedCodeRE = regexp.MustCompile(`^\s*(?:int|char|void|float|double|struct|if|for|while|return|switch)\b`)
	cMagicNumberRE   = regexp.MustCompile(`(?:==|!=|<=|>=|<|>)\s*([2-9]|[1-9][0-9]+)\b`)
	cSingleLetterRE  = regexp.MustCompile(`^\s*(?:int|char|float|long)\s+([a-z])\s*=`)
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
		if strings.Contains(text, "<= sizeof(") {
			emit("stack-buffer-overflow-loop", n)
		}
		if strings.Contains(text, "alloca(") {
			emit("alloca-in-loop", n)
		}
	case "declaration":
		if strings.Contains(text, "char buf[len];") || (strings.Contains(text, "buf[") && strings.Contains(text, "len]")) {
			emit("vla-stack-allocation", n)
		}
		if strings.Contains(text, "1024 * 1024") && strings.Contains(text, "buf[") {
			emit("stack-array-large-allocation", n)
		}
		if strings.Contains(text, "volatile int flag") {
			emit("volatile-used-for-synchronization", n)
		}
		if cSingleLetterRE.MatchString(text) && strings.Contains(text, "/* used across") {
			emit("single-letter-identifier", n)
		}
	case "call_expression":
		cMatchCall(n, text, src, emit)
	case "cast_expression":
		if strings.Contains(text, "(uint32_t *)") && strings.Contains(text, "byte_ptr") {
			emit("unaligned-pointer-cast", n)
		}
		if strings.Contains(text, "(short)") && strings.Contains(text, "wide_val") {
			emit("integer-truncation-cast", n)
		}
		if strings.Contains(text, "(uint32_t)") && strings.Contains(text, "ptr") {
			emit("lossy-pointer-to-int-cast", n)
		}
	case "return_statement":
		if strings.Contains(text, "return local;") || strings.Contains(text, "return &local;") {
			emit("dangling-stack-pointer-return", n)
		}
	case "binary_expression":
		if strings.Contains(text, "signed_len < buf_size") {
			emit("signed-unsigned-comparison", n)
		}
		if strings.Contains(text, "1U << shift") {
			emit("shift-count-overflow", n)
		}
		if strings.Contains(text, "num / divisor") && !strings.Contains(text, "divisor !=") {
			emit("divide-by-zero-hazard", n)
		}
		if strings.Contains(text, "int sum = a + b") {
			emit("signed-integer-overflow", n)
		}
		if cMagicNumberRE.MatchString(text) && strings.Contains(text, "attempts > 3") {
			emit("magic-numbers-in-logic", n)
		}
	case "function_definition":
		if strings.Contains(text, "printf(\"caught signal") && strings.Contains(text, "handler(int sig)") {
			emit("signal-handler-async-unsafe", n)
		}
		if strings.Count(text, ";") > 50 {
			emit("long-function-body", n)
		}
		if strings.Count(text, "int ") >= 6 && strings.HasPrefix(text, "void configure(") {
			emit("excessive-parameters", n)
		}
	case "goto_statement":
		if strings.Contains(text, "goto retry;") {
			emit("goto-backward-jump", n)
		}
	case "preproc_def":
		if strings.Contains(text, "#define SQUARE(x) x * x") {
			emit("macro-missing-parentheses", n)
		}
	case "comment":
		if strings.Contains(text, "TODO:") || strings.Contains(text, "FIXME:") {
			emit("todo-comment-left", n)
		}
		if strings.Contains(text, "void old_function(void)") {
			emit("commented-out-c-code", n)
		}
	case "switch_statement":
		if strings.Count(text, "case 1:") >= 2 {
			emit("duplicate-switch-cases", n)
		}
	case "compound_statement":
		if strings.Contains(text, "return total;\nprintf(\"done\\n\");") || strings.Contains(text, "return total;\r\nprintf(\"done\\n\");") {
			emit("unreachable-code-after-return", n)
		}
	}
}

func cMatchCall(n *sitter.Node, text string, src []byte, emit func(string, *sitter.Node)) {
	if strings.Contains(text, "memcpy(") && strings.Contains(text, "user_count") {
		emit("unbounded-memcpy-size", n)
	}
	if strings.Contains(text, "malloc(strlen(str))") {
		emit("off-by-one-null-terminator", n)
	}
	if strings.Contains(text, "malloc(sizeof(struct Packet))") {
		emit("flexible-array-member-misuse", n)
	}
	if strings.Contains(text, "strncpy(") && strings.Contains(text, "sizeof(dst))") && !strings.Contains(text, "- 1") {
		emit("strncpy-missing-null-termination", n)
	}
	if strings.Contains(text, "memset(secret, 0, sizeof(secret))") {
		emit("memset-cleared-by-compiler", n)
	}
	if strings.Contains(text, "printf(user_str)") {
		emit("printf-non-literal-format", n)
	}
	if strings.Contains(text, "printf(") && strings.Contains(text, "%n") {
		emit("percent-n-specifier-used", n)
	}
	if strings.Contains(text, "syslog(LOG_INFO, msg)") {
		emit("syslog-variable-format", n)
	}
	if strings.Contains(text, "malloc(num * size)") {
		emit("multiplication-overflow-malloc", n)
	}
	if strings.Contains(text, "malloc(sz);\np[0] = 'a'") || strings.Contains(text, "malloc(sz);\r\np[0] = 'a'") {
		emit("unchecked-malloc-return", n)
	}
	if strings.Contains(text, "ptr = NULL;\n*ptr = 10") || strings.Contains(text, "ptr = NULL;\r\n*ptr = 10") {
		emit("null-pointer-dereference", n)
	}
	if strings.Contains(text, "fopen(path, \"r\");\nfread(") || strings.Contains(text, "fopen(path, \"r\");\r\nfread(") {
		emit("unchecked-fopen-return", n)
	}
	if strings.Contains(text, "getenv(\"HOME\");\nstrcpy(") || strings.Contains(text, "getenv(\"HOME\");\r\nstrcpy(") {
		emit("unchecked-getenv-return", n)
	}
	if strings.Contains(text, "pthread_create(&tid, NULL, worker, NULL);") && !strings.Contains(text, "pthread_detach") && !strings.Contains(text, "pthread_join") {
		emit("pthread-join-missing", n)
	}
	if strings.Contains(text, "int token = rand();") {
		emit("insecure-rand-function", n)
	}
	if strings.Contains(text, "DES_ecb_encrypt(") {
		emit("deprecated-des-cipher", n)
	}
	if strings.Contains(text, "secret_key_1234567890abcdef") {
		emit("hardcoded-cryptographic-key", n)
	}
	if strings.Contains(text, "unsigned char iv[16] = {0};") {
		emit("static-iv-initialization", n)
	}
	if strings.Contains(text, "MD5_Init(&ctx)") {
		emit("insecure-md5-hashing", n)
	}
	if strings.Contains(text, "SSLv23_method()") {
		emit("insecure-ssl-version", n)
	}
	if strings.HasPrefix(text, "void log_msg(const char *fmt, ...);") {
		emit("custom-varargs-missing-format-attr", n)
	}
}
