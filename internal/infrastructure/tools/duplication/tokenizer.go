package duplication

import "strings"

// commentSyntax is a language's comment delimiters used to strip comments before tokenizing (a comment
// change must not hide or fabricate a clone). Languages absent here are tokenized without comment
// stripping (a conservative default – comment tokens simply participate, which cannot create a false
// clone across differently-commented code any more than code itself can).
type commentSyntax struct {
	line       []string
	blockStart string
	blockEnd   string
}

var syntaxByLang = map[string]commentSyntax{
	"Go": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"}, "JavaScript": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"TypeScript": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"}, "TSX": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"JSX": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"}, "Java": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"Kotlin": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"}, "Scala": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"C": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"}, "C++": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"C#": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"}, "Rust": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"Swift": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"}, "Dart": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"PHP":    {line: []string{"//", "#"}, blockStart: "/*", blockEnd: "*/"},
	"Python": {line: []string{"#"}}, "Ruby": {line: []string{"#"}}, "Shell": {line: []string{"#"}}, "YAML": {line: []string{"#"}},
	"SQL": {line: []string{"--"}}, "Lua": {line: []string{"--"}},
}

// tokenize splits content into tokens (comment- and whitespace-insensitive) and returns them plus the
// number of code lines (lines that produced at least one token). A token is a maximal run of
// identifier/number characters, or a single punctuation character. Comments are stripped line- and
// block-wise. Limitation: a comment marker inside a string literal is treated as a comment (rare;
// documented) – the same simplification the code-inventory line classifier makes.
func tokenize(lang string, content []byte) (toks []token, codeLines int) {
	syn := syntaxByLang[lang]
	inBlock := false
	lineNo := 0
	for _, raw := range strings.Split(string(content), "\n") {
		lineNo++
		code := stripComments(raw, syn, &inBlock)
		before := len(toks)
		tokenizeLine(code, lineNo, &toks)
		if len(toks) > before {
			codeLines++
		}
	}
	return toks, codeLines
}

// stripComments removes comment text from one line, tracking multi-line block state via inBlock.
func stripComments(line string, syn commentSyntax, inBlock *bool) string {
	if *inBlock {
		if syn.blockEnd == "" {
			return ""
		}
		if idx := strings.Index(line, syn.blockEnd); idx >= 0 {
			*inBlock = false
			return stripComments(line[idx+len(syn.blockEnd):], syn, inBlock)
		}
		return ""
	}
	// earliest of: a block-start or any line-comment marker
	cut := -1
	blockAt := -1
	if syn.blockStart != "" {
		blockAt = strings.Index(line, syn.blockStart)
	}
	lineAt := -1
	for _, lc := range syn.line {
		if lc == "" {
			continue
		}
		if i := strings.Index(line, lc); i >= 0 && (lineAt < 0 || i < lineAt) {
			lineAt = i
		}
	}
	switch {
	case blockAt >= 0 && (lineAt < 0 || blockAt < lineAt):
		rest := line[blockAt+len(syn.blockStart):]
		if syn.blockEnd != "" {
			if idx := strings.Index(rest, syn.blockEnd); idx >= 0 {
				return line[:blockAt] + " " + stripComments(rest[idx+len(syn.blockEnd):], syn, inBlock)
			}
		}
		*inBlock = true
		return line[:blockAt]
	case lineAt >= 0:
		cut = lineAt
		return line[:cut]
	default:
		return line
	}
}

func isWord(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// opChars are the characters that combine into a single operator token (so `!=`, `<=`, `&&`, `->`, `=>`,
// `::`, `+=` count as one token, matching a real lexer's granularity rather than one-per-character).
func isOpChar(b byte) bool {
	switch b {
	case '+', '-', '*', '/', '%', '=', '<', '>', '!', '&', '|', '^', '~', '?', ':':
		return true
	}
	return false
}

// tokenizeLine appends the tokens of a comment-stripped line, at roughly lexer granularity: an
// identifier/number run, a whole string literal, a run of operator characters, or a single structural
// punctuation char. A string literal that is not closed on the same line yields one token to end of line
// (the walk is line-based; multi-line raw strings/templates are a documented edge).
func tokenizeLine(line string, lineNo int, toks *[]token) {
	i := 0
	for i < len(line) {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '"' || c == '\'' || c == '`':
			j := i + 1
			for j < len(line) {
				if line[j] == '\\' && j+1 < len(line) { // skip an escaped char (e.g. \" \\)
					j += 2
					continue
				}
				if line[j] == c {
					j++
					break
				}
				j++
			}
			*toks = append(*toks, token{text: line[i:j], line: lineNo})
			i = j
		case isWord(c):
			j := i + 1
			for j < len(line) && isWord(line[j]) {
				j++
			}
			*toks = append(*toks, token{text: line[i:j], line: lineNo})
			i = j
		case isOpChar(c):
			j := i + 1
			for j < len(line) && isOpChar(line[j]) {
				j++
			}
			*toks = append(*toks, token{text: line[i:j], line: lineNo})
			i = j
		default:
			*toks = append(*toks, token{text: string(c), line: lineNo})
			i++
		}
	}
}
