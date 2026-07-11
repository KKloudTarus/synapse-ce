package codeanalysis

import (
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// kind values for a rule (mirrors finding.KindQuality / finding.KindReliability without importing domain
// into the pattern table).
const (
	kindQuality     = "quality"
	kindReliability = "reliability"
)

// rule is one deterministic maintainability/reliability check over a source line. Either re or match is
// used (match is for checks that need same-token equality, which RE2 cannot express without backrefs).
// skip filters false positives; exts, when non-nil, restricts the rule to those (lower-case) extensions.
type rule struct {
	id       string
	kind     string
	cwe      string
	severity shared.Severity
	title    string
	desc     string
	re       *regexp.Regexp
	match    func(line string) bool
	skip     func(line string) bool
	exts     map[string]bool
}

func (r *rule) hit(line string) bool {
	if r.skip != nil && r.skip(line) {
		return false
	}
	if r.match != nil {
		return r.match(line)
	}
	return r.re != nil && r.re.MatchString(line)
}

func (r *rule) appliesTo(ext string) bool { return r.exts == nil || r.exts[ext] }

// commentOnlyLine reports whether a trimmed line is a pure comment (so code-only rules can skip it).
func commentOnlyLine(line string) bool {
	l := strings.TrimSpace(line)
	return strings.HasPrefix(l, "//") || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "*") ||
		strings.HasPrefix(l, "/*") || strings.HasPrefix(l, "--")
}

// looksLikeCode reports whether a comment's body looks like commented-out code (ends in a statement
// terminator or brace and contains an identifier), not prose.
var codeTail = regexp.MustCompile(`[A-Za-z0-9_)\]]\s*[;{}]\s*$`)

func commentedOutCode(line string) bool {
	l := strings.TrimSpace(line)
	var body string
	switch {
	case strings.HasPrefix(l, "//"):
		body = strings.TrimSpace(l[2:])
	case strings.HasPrefix(l, "#"):
		body = strings.TrimSpace(l[1:])
	default:
		return false
	}
	if body == "" || strings.HasPrefix(body, "!") { // shebang etc.
		return false
	}
	return codeTail.MatchString(body) && strings.ContainsAny(body, "=(")
}

// maskStrings replaces the contents of string/char literals ("...", '...', `...`) with spaces, so an
// operator or identifier INSIDE a string is never matched as code (e.g. log("x == x") is not a
// self-comparison). Escapes are honored. Length/positions are preserved.
func maskStrings(l string) string {
	b := []byte(l)
	i := 0
	for i < len(b) {
		c := b[i]
		if c == '"' || c == '\'' || c == '`' {
			b[i] = ' '
			i++
			for i < len(b) {
				if b[i] == '\\' && i+1 < len(b) {
					b[i], b[i+1] = ' ', ' '
					i += 2
					continue
				}
				if b[i] == c {
					b[i] = ' '
					i++
					break
				}
				b[i] = ' '
				i++
			}
			continue
		}
		i++
	}
	return string(b)
}

// stripTrailingComment removes a trailing line comment (// or space-# ) so an assignment with a trailing
// note still parses. It does not attempt to respect string literals (a rare edge for these checks).
func stripTrailingComment(l string) string {
	if i := strings.Index(l, "//"); i >= 0 {
		l = l[:i]
	}
	if i := strings.Index(l, " #"); i >= 0 {
		l = l[:i]
	}
	return l
}

// selfAssignment reports whether the whole statement is `<ident> = <ident>` (same identifier), e.g.
// `y = y;` – a no-op. The right side must be ONLY the identifier, so `total = total + 1` does not match.
func selfAssignment(line string) bool {
	l := strings.TrimSpace(stripTrailingComment(maskStrings(line)))
	l = strings.TrimSpace(strings.TrimSuffix(l, ";"))
	idx := findOperator(l, "=")
	if idx < 0 {
		return false
	}
	lhs := strings.TrimSpace(l[:idx])
	rhs := strings.TrimSpace(l[idx+1:])
	return lhs != "" && lhs == rhs && isIdentPath(lhs)
}

// selfComparison reports whether any `==` (or `!=`) compares an operand to itself, e.g. `if (x == x)` or
// `a && y.z != y.z`. It inspects the identifier-path operands ADJACENT to each operator, so it works
// inside a larger expression, not only on a bare statement.
func selfComparison(line string) bool {
	masked := maskStrings(line)
	for _, op := range []string{"==", "!="} {
		l := masked
		base := 0
		for {
			rel := findOperator(l[base:], op)
			if rel < 0 {
				break
			}
			idx := base + rel
			lhs := identBefore(l, idx)
			rhs := identAfter(l, idx+len(op))
			if lhs != "" && lhs == rhs && isIdentPath(lhs) {
				return true
			}
			base = idx + len(op)
		}
	}
	return false
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '.' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// identBefore returns the identifier-path token ending just before idx (skipping spaces).
func identBefore(s string, idx int) string {
	j := idx
	for j > 0 && s[j-1] == ' ' {
		j--
	}
	end := j
	for j > 0 && isIdentByte(s[j-1]) {
		j--
	}
	return s[j:end]
}

// identAfter returns the identifier-path token starting just after pos (skipping spaces).
func identAfter(s string, pos int) string {
	i := pos
	for i < len(s) && s[i] == ' ' {
		i++
	}
	start := i
	for i < len(s) && isIdentByte(s[i]) {
		i++
	}
	return s[start:i]
}

// findOperator returns the index of a standalone `op` ("=" or "==") that is not part of a longer operator
// (:=, +=, <=, >=, !=, ==, ===). Returns -1 if none.
func findOperator(s, op string) int {
	for i := 0; i+len(op) <= len(s); i++ {
		if s[i:i+len(op)] != op {
			continue
		}
		prev := byte(' ')
		if i > 0 {
			prev = s[i-1]
		}
		next := byte(' ')
		if i+len(op) < len(s) {
			next = s[i+len(op)]
		}
		if op == "=" {
			if strings.IndexByte("=!<>+-*/%:&|^~", prev) >= 0 || next == '=' {
				continue // part of ==, :=, +=, etc.
			}
		} else { // "=="
			if prev == '=' || prev == '!' || prev == '<' || prev == '>' || next == '=' {
				continue // part of ===, !==, <==, >==
			}
		}
		return i
	}
	return -1
}

func isIdentPath(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	// reject a pure number and a leading digit (not an identifier)
	if s[0] >= '0' && s[0] <= '9' {
		return false
	}
	return true
}

// builtinRules is the tier-1 maintainability + reliability rule set. Precision-biased, deterministic; the
// set grows over time like the SAST rules. Metric-derived rules (complexity, duplication) are added by the
// codequality usecase, not here.
func builtinRules() []rule {
	return []rule{
		{
			id: "quality-todo-comment", kind: kindQuality, cwe: "CWE-546", severity: shared.SeverityInfo,
			title: "Unresolved TODO/FIXME marker",
			desc:  "A TODO/FIXME/HACK/XXX/BUG marker flags unfinished or known-problematic code left in the tree. Track it in an issue and resolve it.",
			re:    regexp.MustCompile(`(?i)(//|#|/\*|\*|--)\s*.*\b(TODO|FIXME|HACK|XXX|BUG)\b`),
		},
		{
			id: "quality-commented-out-code", kind: kindQuality, cwe: "", severity: shared.SeverityInfo,
			title: "Commented-out code",
			desc:  "A comment appears to contain commented-out code, which rots and confuses readers. Delete it – version control preserves history.",
			match: commentedOutCode,
		},
		{
			id: "reliability-empty-catch", kind: kindReliability, cwe: "CWE-390", severity: shared.SeverityMedium,
			title: "Empty exception handler swallows errors",
			desc:  "An empty catch/except block silently swallows an error, hiding failures and complicating debugging. Handle, log, or rethrow the exception.",
			re:    regexp.MustCompile(`(catch\s*\([^)]*\)\s*\{\s*\}|except\b[^\n:]*:\s*pass\b)`),
			skip:  commentOnlyLine,
		},
		{
			id: "reliability-self-assignment", kind: kindReliability, cwe: "CWE-1164", severity: shared.SeverityMedium,
			title: "Self-assignment has no effect",
			desc:  "A variable is assigned to itself (x = x), which is a no-op and usually signals a typo or a lost assignment. Fix the intended target.",
			match: selfAssignment,
			skip:  commentOnlyLine,
		},
		{
			id: "reliability-self-comparison", kind: kindReliability, cwe: "CWE-571", severity: shared.SeverityMedium,
			title: "Comparison of a value to itself",
			desc:  "A value is compared to itself (a == a / a != a), which is constant and usually a typo for a different operand. Fix the comparison.",
			match: selfComparison,
			skip:  commentOnlyLine,
		},
	}
}
