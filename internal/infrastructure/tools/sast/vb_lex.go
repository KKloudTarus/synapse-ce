package sast

import (
	"regexp"
	"strings"
)

var vbAssignmentNameRE = regexp.MustCompile(`(?i)^\s*(?:Dim\s+)?([A-Za-z_]\w*)\s*(?:As\s+\w+\s*)?=`)

func vbAssignmentName(code string) string {
	match := vbAssignmentNameRE.FindStringSubmatch(code)
	if len(match) != 2 {
		return ""
	}
	return strings.ToLower(match[1])
}

func vbCryptoName(name string) bool {
	for _, marker := range []string{"key", "secret", "nonce"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return name == "iv" || strings.HasPrefix(name, "iv_") || strings.HasSuffix(name, "_iv")
}

func vbIVName(name string) bool {
	return name == "iv" || strings.HasPrefix(name, "iv_") || strings.HasSuffix(name, "_iv")
}

// vbCodeOnly masks strings and comments while preserving byte offsets.
func vbCodeOnly(line string) string {
	masked := []byte(line)
	mask := func(start, end int) {
		for i := start; i < end; i++ {
			masked[i] = ' '
		}
	}

	for i := 0; i < len(line); {
		switch {
		case line[i] == '\'':
			mask(i, len(line))
			return string(masked)
		case line[i] == '"':
			start := i
			i++
			for i < len(line) {
				if line[i] != '"' {
					i++
					continue
				}
				if i+1 < len(line) && line[i+1] == '"' {
					i += 2
					continue
				}
				i++
				break
			}
			mask(start, i)
		case vbREMComment(line, i):
			mask(i, len(line))
			return string(masked)
		default:
			i++
		}
	}
	return string(masked)
}

func vbREMComment(line string, i int) bool {
	if i+3 > len(line) || !strings.EqualFold(line[i:i+3], "rem") {
		return false
	}
	if i+3 < len(line) && line[i+3] != ' ' && line[i+3] != '\t' {
		return false
	}
	for j := i - 1; j >= 0; j-- {
		switch line[j] {
		case ' ', '\t':
			continue
		case ':':
			return true
		default:
			return false
		}
	}
	return true
}

func vbRuleMatches(r *rule, raw, code string) bool {
	if r.skip(raw) {
		return false
	}
	if r.id == "vb:todo-marker" {
		return vbTODOCommentMatches(raw)
	}
	if r.id == "vb:async-sub-api" && strings.Contains(strings.ToLower(code), " handles ") {
		return false
	}
	if vbSpecialPrecisionRule(r.id) {
		return r.re.MatchString(raw) && !vbFalsePositive(r.id, code)
	}
	if !vbRuleNeedsRaw(r.id) {
		return r.re.MatchString(code) && !vbFalsePositive(r.id, code)
	}
	return vbRawRuleMatches(r, raw, code)
}

// vbGenericRuleMatches suppresses comment-only input while preserving executable literals for generic rules.
func vbGenericRuleMatches(r *rule, raw, code string) bool {
	if r.skip(raw) {
		return false
	}
	return vbRawRuleMatches(r, raw, code)
}

func vbRawRuleMatches(r *rule, raw, code string) bool {
	for _, match := range r.re.FindAllStringIndex(raw, -1) {
		if vbRawMatchStartsInCode(raw, code, match[0]) || vbLiteralMatchHasCodePrefix(raw, code, match[0]) {
			return true
		}
	}
	return false
}

func vbSpecialPrecisionRule(id string) bool {
	switch id {
	case "vb:hardcoded-crypto-key", "vb:static-iv":
		return true
	default:
		return false
	}
}

func vbFalsePositive(id, code string) bool {
	lower := strings.ToLower(code)
	switch id {
	case "vb:floating-point-equality":
		return !strings.Contains(lower, "if ") && !strings.Contains(lower, "while ") && !strings.Contains(lower, "until ")
	case "vb:hardcoded-crypto-key":
		return !vbCryptoName(vbAssignmentName(code))
	case "vb:static-iv":
		return !vbIVName(vbAssignmentName(code))
	case "vb:task-result", "vb:task-result-blocking":
		return !strings.Contains(lower, "async")
	case "vb:thread-abort", "vb:thread-abort-concurrency":
		return !strings.Contains(lower, "thread")
	default:
		return false
	}
}

func vbTODOCommentMatches(raw string) bool {
	for i := 0; i < len(raw); {
		switch {
		case raw[i] == '\'':
			return vbTODOMarker(raw[i+1:])
		case raw[i] == '"':
			i = vbStringEnd(raw, i)
		case vbREMComment(raw, i):
			return vbTODOMarker(raw[i+3:])
		default:
			i++
		}
	}
	return false
}

func vbTODOMarker(text string) bool {
	text = strings.ToLower(text)
	for _, marker := range []string{"todo", "fixme", "hack"} {
		if i := strings.Index(text, marker); i >= 0 && (i == 0 || !vbWordByte(text[i-1])) && (i+len(marker) == len(text) || !vbWordByte(text[i+len(marker)])) {
			return true
		}
	}
	return false
}

func vbWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_'
}

func vbStringEnd(line string, start int) int {
	for i := start + 1; i < len(line); i++ {
		if line[i] == '"' && i+1 < len(line) && line[i+1] == '"' {
			i++
			continue
		}
		if line[i] == '"' {
			return i + 1
		}
	}
	return len(line)
}

func vbRawMatchStartsInCode(raw, code string, start int) bool {
	return start < len(raw) && start < len(code) && code[start] == raw[start] && !isVBWhitespace(raw[start])
}

func vbLiteralMatchHasCodePrefix(raw, code string, start int) bool {
	stringStart, ok := vbStringStartContaining(raw, start)
	if !ok {
		return false
	}
	statementStart := 0
	for i := 0; i < stringStart; i++ {
		if code[i] == ':' {
			statementStart = i + 1
		}
	}
	prefix := strings.TrimSpace(code[statementStart:stringStart])
	return strings.Contains(prefix, "=") || strings.HasSuffix(prefix, "(")
}

func vbStringStartContaining(line string, want int) (int, bool) {
	for i := 0; i < len(line); {
		switch {
		case line[i] == '\'':
			return 0, false
		case vbREMComment(line, i):
			return 0, false
		case line[i] != '"':
			i++
		default:
			start := i
			i = vbStringEnd(line, i)
			if start <= want && want < i {
				return start, true
			}
		}
	}
	return 0, false
}

func isVBWhitespace(b byte) bool { return b == ' ' || b == '\t' }

func vbRuleNeedsRaw(id string) bool {
	switch id {
	case "vb:sql-concat", "vb:sql-interpolated-string", "vb:sql-string-format",
		"vb:sql-command-text-concat", "vb:process-start-concat",
		"vb:process-startinfo-arguments-concat", "vb:request-admin-role-grant",
		"vb:authorization-allow-all", "vb:hardcoded-conn-string", "vb:hardcoded-password", "vb:cleartext-http",
		"vb:todo-marker", "vb:string-endswith-no-comparison", "vb:repeated-string-concat",
		"hardcoded-credential", "hardcoded-aws-access-key", "private-key-material", "jwt-hardcoded-secret-or-none":
		return true
	default:
		return false
	}
}
