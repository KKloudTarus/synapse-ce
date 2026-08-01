package sast

import "strings"

// scalaLexState masks non-code text while preserving byte offsets for line rules.
// Scala block comments may nest, and triple-quoted strings may span lines.
type scalaLexState struct {
	blockCommentDepth int
	inTripleString    bool
}

func (s *scalaLexState) codeOnly(line string) string {
	masked := []byte(line)
	mask := func(start, end int) {
		for i := start; i < end; i++ {
			masked[i] = ' '
		}
	}

	for i := 0; i < len(line); {
		if s.inTripleString {
			end := strings.Index(line[i:], `"""`)
			if end < 0 {
				mask(i, len(line))
				break
			}
			end += i + 3
			mask(i, end)
			s.inTripleString = false
			i = end
			continue
		}

		if s.blockCommentDepth > 0 {
			switch {
			case strings.HasPrefix(line[i:], "/*"):
				mask(i, i+2)
				s.blockCommentDepth++
				i += 2
			case strings.HasPrefix(line[i:], "*/"):
				mask(i, i+2)
				s.blockCommentDepth--
				i += 2
			default:
				mask(i, i+1)
				i++
			}
			continue
		}

		switch {
		case strings.HasPrefix(line[i:], "//"):
			mask(i, len(line))
			i = len(line)
		case strings.HasPrefix(line[i:], "/*"):
			mask(i, i+2)
			s.blockCommentDepth = 1
			i += 2
		case strings.HasPrefix(line[i:], `"""`):
			mask(i, i+3)
			s.inTripleString = true
			i += 3
		case line[i] == '"':
			end, _ := scalaQuotedEnd(line, i, '"')
			mask(i, end)
			i = end
		case line[i] == '\'':
			end, ok := scalaQuotedEnd(line, i, '\'')
			if !ok {
				i++
				continue
			}
			mask(i, end)
			i = end
		default:
			i++
		}
	}

	return string(masked)
}

func scalaQuotedEnd(line string, start int, quote byte) (int, bool) {
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

func scalaRuleMatches(r *rule, raw, code string) bool {
	if r.id != "scala:sql-interpolation" {
		return r.re.MatchString(code) && !r.skip(code)
	}
	if r.skip(raw) {
		return false
	}

	// The SQL rule needs the interpolated string contents, but its sink must
	// begin in executable code rather than in a string or comment.
	for _, match := range r.re.FindAllStringIndex(raw, -1) {
		if match[0] < len(code) && code[match[0]] != ' ' {
			return true
		}
	}
	return false
}
