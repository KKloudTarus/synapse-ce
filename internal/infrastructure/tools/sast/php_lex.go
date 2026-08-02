package sast

import (
	"strings"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
)

type phpLineView struct {
	text string // PHP text with comments/template content masked; literals retained
	code string // executable PHP only; comments, template content, and literals masked
}

// phpLexState masks non-code regions while preserving byte offsets for line rules.
type phpLexState struct {
	initialized         bool
	template            bool
	inPHP               bool
	blockComment        bool
	quote               byte
	backtick            bool
	heredoc             string
	sawOpenTag          bool
	sawMalformedOpenTag bool
}

func newPHPLexState(template, inPHP bool) phpLexState {
	return phpLexState{initialized: true, template: template, inPHP: inPHP}
}

func (s *phpLexState) codeOnly(line string) string { return s.views(line).code }

func (s *phpLexState) views(line string) phpLineView {
	if !s.initialized {
		s.initialized = true
		s.inPHP = true
	}
	text := []byte(line)
	code := []byte(line)
	mask := func(dst []byte, start, end int) {
		for i := start; i < end; i++ {
			dst[i] = ' '
		}
	}
	maskBoth := func(start, end int) {
		mask(text, start, end)
		mask(code, start, end)
	}

	start := 0
	if s.heredoc != "" {
		end, ok := phpHeredocEnd(line, s.heredoc)
		if !ok {
			mask(code, 0, len(line))
			return phpLineView{text: string(text), code: string(code)}
		}
		mask(code, 0, end)
		s.heredoc = ""
		start = end
	}

	for i := start; i < len(line); {
		if s.template && !s.inPHP {
			open, size := phpOpenTag(line, i)
			if malformed := phpMalformedOpenTag(line, i); malformed >= 0 && (open < 0 || malformed < open) {
				s.sawMalformedOpenTag = true
			}
			if open < 0 {
				maskBoth(i, len(line))
				break
			}
			if size == 2 {
				maskBoth(i, open)
				mask(code, open, open+size)
			} else {
				maskBoth(i, open+size)
			}
			s.inPHP = true
			s.sawOpenTag = true
			i = open + size
			continue
		}
		if s.blockComment {
			if strings.HasPrefix(line[i:], "*/") {
				maskBoth(i, i+2)
				s.blockComment = false
				i += 2
				continue
			}
			maskBoth(i, i+1)
			i++
			continue
		}
		if s.quote != 0 {
			end, closed := phpQuotedEnd(line, i, s.quote, true)
			mask(code, i, end)
			if closed {
				s.quote = 0
			}
			i = end
			continue
		}
		if s.backtick {
			end, closed := phpQuotedEnd(line, i, '`', true)
			mask(code, i, end)
			if closed {
				s.backtick = false
			}
			i = end
			continue
		}

		switch {
		case phpMalformedOpenTagAt(line, i):
			s.sawMalformedOpenTag = true
			i++
		case phpTagSizeAt(line, i) > 0:
			size := phpTagSizeAt(line, i)
			maskBoth(i, i+size)
			s.inPHP = true
			s.sawOpenTag = true
			i += size
		case s.template && strings.HasPrefix(line[i:], "?>"):
			s.inPHP = false
			i += 2
		case strings.HasPrefix(line[i:], "//") || line[i] == '#' && !strings.HasPrefix(line[i:], "#["):
			if s.template {
				if close := strings.Index(line[i:], "?>"); close >= 0 {
					close += i
					maskBoth(i, close+2)
					s.inPHP = false
					i = close + 2
					continue
				}
			}
			maskBoth(i, len(line))
			i = len(line)
		case strings.HasPrefix(line[i:], "/*"):
			maskBoth(i, i+2)
			s.blockComment = true
			i += 2
		case strings.HasPrefix(line[i:], "<<<"):
			label, ok := phpHeredocLabel(line[i+3:])
			if !ok {
				i += 3
				continue
			}
			mask(code, i, len(line))
			s.heredoc = label
			i = len(line)
		case line[i] == '\'' || line[i] == '"':
			s.quote = line[i]
			end, closed := phpQuotedEnd(line, i, s.quote, false)
			mask(code, i, end)
			if closed {
				s.quote = 0
			}
			i = end
		case line[i] == '`':
			s.backtick = true
			end, closed := phpQuotedEnd(line, i, '`', false)
			mask(code, i+1, end)
			if closed {
				s.backtick = false
			}
			i = end
		default:
			i++
		}
	}
	return phpLineView{text: string(text), code: string(code)}
}

func phpOpenTag(line string, start int) (int, int) {
	for i := start; i < len(line); i++ {
		if size := phpTagSizeAt(line, i); size > 0 {
			return i, size
		}
	}
	return -1, 0
}

func phpMalformedOpenTag(line string, start int) int {
	for i := start; i < len(line); i++ {
		if phpMalformedOpenTagAt(line, i) {
			return i
		}
	}
	return -1
}

func phpMalformedOpenTagAt(line string, start int) bool {
	return strings.HasPrefix(strings.ToLower(line[start:]), "<?php") && phpTagSizeAt(line, start) == 0
}

// phpLineViews masks PHP comments, literals, and template text while preserving offsets.
// PHTML is always a template; other PHP extensions use tagless mode unless a real opening tag appears.
func phpLineViews(ext string, lines []string) []phpLineView {
	template := ext == ".phtml"
	lex := newPHPLexState(template, !template)
	views := make([]phpLineView, len(lines))
	for i, line := range lines {
		views[i] = lex.views(line)
	}
	if !template && (lex.sawOpenTag || lex.sawMalformedOpenTag) {
		lex = newPHPLexState(true, false)
		for i, line := range lines {
			views[i] = lex.views(line)
		}
	}
	return views
}

func phpContextLines(ext string, lines []string, views []phpLineView) (text, code []string) {
	if !phpExts[ext] {
		return lines, lines
	}
	text = make([]string, len(views))
	code = make([]string, len(views))
	for i := range views {
		text[i] = views[i].text
		code[i] = views[i].code
	}
	return text, code
}

func phpTagSizeAt(line string, start int) int {
	lower := strings.ToLower(line[start:])
	switch {
	case strings.HasPrefix(lower, "<?php") && (len(lower) == 5 || phpWhitespace(lower[5])):
		return 5
	case strings.HasPrefix(lower, "<?="):
		return 3
	case strings.HasPrefix(lower, "<?") && !strings.HasPrefix(lower, "<?php") && !strings.HasPrefix(lower, "<?xml"):
		return 2
	default:
		return 0
	}
}

func phpWhitespace(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '\f':
		return true
	default:
		return false
	}
}

func phpQuotedEnd(line string, start int, quote byte, continuation bool) (int, bool) {
	escaped := false
	begin := start + 1
	if continuation {
		begin = start
	}
	for i := begin; i < len(line); i++ {
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

func phpHeredocLabel(rest string) (string, bool) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false
	}
	quote := byte(0)
	if rest[0] == '\'' || rest[0] == '"' {
		quote = rest[0]
		rest = rest[1:]
	}
	end := 0
	for end < len(rest) && (rest[end] == '_' || rest[end] >= 'a' && rest[end] <= 'z' || rest[end] >= 'A' && rest[end] <= 'Z' || end > 0 && rest[end] >= '0' && rest[end] <= '9') {
		end++
	}
	if end == 0 || quote != 0 && (end >= len(rest) || rest[end] != quote) {
		return "", false
	}
	return rest[:end], true
}

func phpHeredocEnd(line, label string) (int, bool) {
	leading := len(line) - len(strings.TrimLeft(line, " \t"))
	trimmed := line[leading:]
	if !strings.HasPrefix(trimmed, label) {
		return 0, false
	}
	end := leading + len(label)
	if len(trimmed) == len(label) {
		return end, true
	}
	switch trimmed[len(label)] {
	case ';', ',', ')', ']', '}':
		return end + 1, true
	default:
		return 0, false
	}
}

const (
	maxPHPStatementLines = 18
	maxPHPStatementBytes = 64 << 10
)

func phpStatement(lines []string, views []phpLineView, start int) (text, code string, ok, truncated bool) {
	if start < 0 || start >= len(lines) || strings.TrimSpace(views[start].code) == "" {
		return "", "", false, false
	}
	firstText, firstCode := views[start].text, views[start].code
	depth, lastSemi := 0, -1
	for i := range firstCode {
		switch firstCode[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				lastSemi = i
			}
		}
	}
	if lastSemi >= 0 {
		trailing := firstCode[lastSemi+1:]
		if strings.TrimSpace(trailing) == "" || !phpUnfinishedStatement(trailing) {
			return "", "", false, false
		}
		firstText = strings.Repeat(" ", lastSemi+1) + firstText[lastSemi+1:]
		firstCode = strings.Repeat(" ", lastSemi+1) + trailing
	}
	depth = 0
	started := false
	var textParts, codeParts []string
	bytes := 0
	end := min(len(lines), start+maxPHPStatementLines)
	for i := start; i < end; i++ {
		lineText, lineCode := views[i].text, views[i].code
		if i == start {
			lineText, lineCode = firstText, firstCode
		}
		if bytes+len(lines[i])+1 > maxPHPStatementBytes {
			return "", "", false, true
		}
		textParts = append(textParts, lineText)
		codeParts = append(codeParts, lineCode)
		bytes += len(lines[i]) + 1
		terminated := false
		for _, ch := range lineCode {
			switch ch {
			case '(', '[', '{':
				depth++
				started = true
			case ')', ']', '}':
				if depth > 0 {
					depth--
				}
			case ';':
				if depth == 0 {
					terminated = true
				}
			}
		}
		if i > start && (terminated || started && depth == 0) {
			return strings.Join(textParts, "\n"), strings.Join(codeParts, "\n"), true, false
		}
	}
	if len(textParts) > 1 && end == len(lines) {
		return strings.Join(textParts, "\n"), strings.Join(codeParts, "\n"), true, false
	}
	return "", "", false, len(textParts) > 1
}

func phpUnfinishedStatement(code string) bool {
	depth := 0
	for _, ch := range code {
		switch ch {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth > 0
}

func phpClosingTagEligible(ext string) bool {
	return ext != ".phtml"
}

func phpRuleNeedsCodePosition(id string) bool {
	if strings.HasPrefix(id, "php:") {
		return true
	}
	return phpGenericCodeRules[id]
}

var phpGenericCodeRules = map[string]bool{
	"dynamic-code-eval":                    true,
	"generic-sql-dynamic-execute":          true,
	"generic-command-injection-sink":       true,
	"unsafe-deserialization-generic":       true,
	"xxe-insecure-xml-parsing":             true,
	"generic-ssrf-request-url":             true,
	"path-traversal-file-access":           true,
	"open-redirect-user-url":               true,
	"insecure-tls-verify-disabled":         true,
	"insecure-randomness-security-context": true,
}

func phpRuleMatches(r *rule, text, code string) bool {
	_, ok := phpRuleMatchIndex(r, text, code)
	return ok
}

func phpRuleMatchIndex(r *rule, text, code string) (int, bool) {
	if r.skip(text) && !strings.HasPrefix(strings.TrimSpace(text), "#[") {
		return 0, false
	}
	for _, match := range r.re.FindAllStringIndex(text, -1) {
		if r.id == "php:short-open-tag" {
			return match[0], true
		}
		if r.id == "php:backtick-command" && match[0] < len(code) && !phpMaskedByte(code[match[0]]) {
			return match[0], true
		}
		if r.ruleQuality() != domainrule.QualitySecurity {
			for i := match[0]; i < match[1] && i < len(code); i++ {
				if !phpMaskedByte(code[i]) {
					return i, true
				}
			}
			continue
		}
		anchor := match[0]
		for anchor < match[1] && !phpIdentifierByte(text[anchor]) {
			anchor++
		}
		if anchor < match[1] && anchor < len(code) && !phpMaskedByte(code[anchor]) {
			return anchor, true
		}
	}
	return 0, false
}

func phpMaskedByte(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}

func phpIdentifierByte(ch byte) bool {
	return ch == '_' || ch == '$' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}
