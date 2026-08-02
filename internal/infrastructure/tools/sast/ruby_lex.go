package sast

import (
	"path/filepath"
	"strings"
)

// rubyLexState masks Ruby comments and literals while preserving byte offsets.
// It handles =begin/=end comments, heredocs, quoted strings, command strings,
// and paired percent literals. Rules that intentionally inspect an interpolated
// string use rubyRuleMatches, which still requires the sink to start in code.
type rubyLexState struct {
	blockComment bool
	heredocTerm  string
	quote        byte
	percentOpen  byte
	percentClose byte
	percentDepth int
}

func (s *rubyLexState) codeOnly(line string) string {
	masked := []byte(line)
	mask := func(start, end int) {
		if start < 0 {
			start = 0
		}
		if end > len(masked) {
			end = len(masked)
		}
		for i := start; i < end; i++ {
			masked[i] = ' '
		}
	}

	if s.blockComment {
		mask(0, len(line))
		if rubyEmbeddedDocMarker(line, "=end") {
			s.blockComment = false
		}
		return string(masked)
	}
	if rubyEmbeddedDocMarker(line, "=begin") {
		mask(0, len(line))
		s.blockComment = true
		return string(masked)
	}

	if s.heredocTerm != "" {
		mask(0, len(line))
		if strings.TrimSpace(line) == s.heredocTerm {
			s.heredocTerm = ""
		}
		return string(masked)
	}

	start := 0
	if s.quote != 0 {
		end, closed := rubyQuotedEnd(line, -1, s.quote)
		mask(0, end)
		if !closed {
			return string(masked)
		}
		s.quote = 0
		start = end
	}

	for i := start; i < len(line); {
		if s.percentDepth > 0 {
			start := i
			escaped := false
			paired := s.percentOpen != s.percentClose
			for i < len(line) {
				ch := line[i]
				mask(i, i+1)
				i++
				if escaped {
					escaped = false
					continue
				}
				if ch == '\\' {
					escaped = true
					continue
				}
				if paired && ch == s.percentOpen {
					s.percentDepth++
					continue
				}
				if ch == s.percentClose {
					s.percentDepth--
					if s.percentDepth == 0 {
						s.percentOpen, s.percentClose = 0, 0
						break
					}
				}
			}
			if i == start { // defensive; the loop must always advance
				i++
			}
			continue
		}

		switch {
		case line[i] == '#':
			mask(i, len(line))
			i = len(line)
		case line[i] == '\'' || line[i] == '"' || line[i] == '`':
			quote := line[i]
			end, closed := rubyQuotedEnd(line, i, quote)
			mask(i, end)
			if quote == '`' {
				masked[i] = '`'
			}
			if !closed {
				s.quote = quote
			}
			i = end
		case line[i] == '/' && rubyRegexLiteralStart(line, i):
			end, closed := rubyQuotedEnd(line, i, '/')
			mask(i, end)
			if !closed {
				s.quote = '/'
			}
			i = end
		case line[i] == '%':
			openPos, open, close, ok := rubyPercentStart(line, i)
			if !ok {
				i++
				continue
			}
			commandLiteral := i+1 < len(line) && line[i+1] == 'x'
			mask(i, openPos+1)
			if commandLiteral {
				masked[i] = '%'
				masked[i+1] = 'x'
			}
			s.percentOpen, s.percentClose, s.percentDepth = open, close, 1
			i = openPos + 1
		case strings.HasPrefix(line[i:], "<<"):
			term, ok := rubyHeredocTerm(line, i)
			if !ok {
				i += 2
				continue
			}
			mask(i, len(line))
			s.heredocTerm = term
			i = len(line)
		default:
			i++
		}
	}

	return string(masked)
}

func rubyQuotedEnd(line string, start int, quote byte) (int, bool) {
	escaped := false
	for i := start + 1; i < len(line); i++ {
		if escaped {
			escaped = false
			continue
		}
		if line[i] == '\\' {
			escaped = true
			continue
		}
		if line[i] == quote {
			return i + 1, true
		}
	}
	return len(line), false
}

func rubyEmbeddedDocMarker(line, marker string) bool {
	if !strings.HasPrefix(line, marker) {
		return false
	}
	return len(line) == len(marker) || line[len(marker)] == ' ' || line[len(marker)] == '\t'
}

func rubyRegexLiteralStart(line string, start int) bool {
	for i := start - 1; i >= 0; i-- {
		if line[i] == ' ' || line[i] == '\t' {
			continue
		}
		return strings.ContainsRune("=([{,:;!&|?~", rune(line[i]))
	}
	return true
}

func rubyPercentStart(line string, start int) (openPos int, open, close byte, ok bool) {
	if start+1 >= len(line) || line[start] != '%' {
		return 0, 0, 0, false
	}
	j := start + 1
	if strings.ContainsRune("qQwWiIxrs", rune(line[j])) {
		j++
		if j >= len(line) {
			return 0, 0, 0, false
		}
	}
	delim := line[j]
	if delim == ' ' || delim == '\t' || (delim >= '0' && delim <= '9') ||
		(delim >= 'A' && delim <= 'Z') || (delim >= 'a' && delim <= 'z') || delim == '_' {
		return 0, 0, 0, false
	}
	close = delim
	switch delim {
	case '(':
		close = ')'
	case '[':
		close = ']'
	case '{':
		close = '}'
	case '<':
		close = '>'
	}
	return j, delim, close, true
}

func rubyHeredocTerm(line string, start int) (string, bool) {
	if !strings.HasPrefix(line[start:], "<<") {
		return "", false
	}
	if start > 0 && rubyIdentifierPart(line[start-1]) {
		return "", false
	}
	j := start + 2
	if j < len(line) && (line[j] == '-' || line[j] == '~') {
		j++
	}
	if j >= len(line) {
		return "", false
	}

	if line[j] == '\'' || line[j] == '"' || line[j] == '`' {
		quote := line[j]
		j++
		begin := j
		for j < len(line) && line[j] != quote {
			j++
		}
		if j == begin || j >= len(line) {
			return "", false
		}
		return line[begin:j], true
	}

	// Avoid treating the common append form `value << item` as a heredoc. Ruby
	// heredoc identifiers are adjacent to << (or <<-/<<~) and may be lowercase.
	if !rubyIdentifierStart(line[j]) {
		return "", false
	}
	begin := j
	for j < len(line) {
		ch := line[j]
		if rubyIdentifierPart(ch) {
			j++
			continue
		}
		break
	}
	return line[begin:j], j > begin
}

func rubyIdentifierStart(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_'
}

func rubyIdentifierPart(ch byte) bool {
	return rubyIdentifierStart(ch) || (ch >= '0' && ch <= '9')
}

func rubyRuleMatches(r *rule, raw, code string) bool {
	switch r.id {
	case "rb:sql-interpolation", "rb:sql-concatenation", "rb:command-injection", "rb:weak-cipher", "rb:insecure-cipher-mode":
		if r.skip(raw) {
			return false
		}
		for _, match := range r.re.FindAllStringIndex(raw, -1) {
			if match[0] >= len(code) || code[match[0]] == ' ' {
				continue
			}
			if r.id == "rb:command-injection" && (raw[match[0]] == '`' || strings.HasPrefix(raw[match[0]:], "%x")) {
				if rubyCommandLiteralHasTaintedInterpolation(raw, match[0]) {
					return true
				}
				continue
			}
			return true
		}
		return false
	default:
		return r.re.MatchString(code) && !r.skip(code)
	}
}

func rubyCommandLiteralHasTaintedInterpolation(line string, start int) bool {
	contentStart, contentEnd, ok := rubyCommandLiteralBounds(line, start)
	if !ok {
		return false
	}
	content := line[contentStart:contentEnd]
	for offset := 0; offset < len(content); {
		rel := strings.Index(content[offset:], "#{")
		if rel < 0 {
			return false
		}
		value := strings.TrimLeft(content[offset+rel+2:], " \t")
		for _, source := range []string{"params", "request", "cookies", "session", "ENV"} {
			if strings.HasPrefix(value, source) && (len(value) == len(source) || !rubyIdentifierPart(value[len(source)])) {
				return true
			}
		}
		offset += rel + 2
	}
	return false
}

func rubyCommandLiteralBounds(line string, start int) (int, int, bool) {
	if start >= len(line) {
		return 0, 0, false
	}
	if line[start] == '`' {
		end, closed := rubyQuotedEnd(line, start, '`')
		if !closed {
			return start + 1, len(line), true
		}
		return start + 1, end - 1, true
	}
	if !strings.HasPrefix(line[start:], "%x") {
		return 0, 0, false
	}
	openPos, open, close, ok := rubyPercentStart(line, start)
	if !ok {
		return 0, 0, false
	}
	depth := 1
	escaped := false
	paired := open != close
	for i := openPos + 1; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if paired && ch == open {
			depth++
			continue
		}
		if ch == close {
			depth--
			if depth == 0 {
				return openPos + 1, i, true
			}
		}
	}
	return openPos + 1, len(line), true
}

// rubyERBLexState exposes only executable ERB tag contents to Ruby rules.
// Static template text and ERB comments remain masked with byte offsets intact.
type rubyERBLexState struct {
	ruby    rubyLexState
	inCode  bool
	comment bool
}

func (s *rubyERBLexState) codeOnly(line string) string {
	masked := make([]byte, len(line))
	for i := range masked {
		masked[i] = ' '
	}

	for offset := 0; offset < len(line); {
		if !s.inCode {
			rel := strings.Index(line[offset:], "<%")
			if rel < 0 {
				break
			}
			open := offset + rel
			if strings.HasPrefix(line[open:], "<%%") {
				offset = open + 3
				continue
			}
			s.inCode = true
			s.comment = strings.HasPrefix(line[open:], "<%#")
			offset = open + 2
			if offset < len(line) && (line[offset] == '=' || line[offset] == '-') {
				offset++
			}
		}

		closeRel := strings.Index(line[offset:], "%>")
		if closeRel < 0 {
			if !s.comment {
				copy(masked[offset:], s.ruby.codeOnly(line[offset:]))
			}
			break
		}
		close := offset + closeRel
		if !s.comment {
			copy(masked[offset:close], s.ruby.codeOnly(line[offset:close]))
		}
		s.inCode = false
		s.comment = false
		offset = close + 2
	}
	return string(masked)
}

// sastSourceExt returns a language-gating extension for files whose ecosystem
// convention uses an extensionless Ruby DSL filename.
func sastSourceExt(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != "" {
		return ext
	}
	switch strings.ToLower(filepath.Base(path)) {
	case "gemfile", "rakefile", "capfile", "guardfile", "podfile", "fastfile", "appraisals", "berksfile", "thorfile", "vagrantfile":
		return ".rb"
	default:
		return ""
	}
}
