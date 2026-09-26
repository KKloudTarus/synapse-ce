package sast

import (
	"regexp"
	"strings"
)

// jsLexState masks JavaScript/TypeScript COMMENT text while preserving byte offsets, so no rule can
// match on commented-out code. String and template literals are skipped over but NOT masked: many
// rules need the literal's content (a SQL string, a URL, a credential), and only the comment is
// noise. Block comments and unterminated template literals carry across lines, which is why this is
// a state machine rather than a per-line regex — the same shape as ruby_lex.go and scala_lex.go.
//
// Known bound: a regular-expression literal that contains an unescaped "/*" would be read as a
// block comment. The escaped form (/\/*/) is handled; the unescaped one is rare enough to accept
// rather than pay for a full JS tokenizer here.
type jsLexState struct {
	inBlockComment bool
	inTemplate     bool
}

func (s *jsLexState) codeOnly(line string) string {
	masked := []byte(line)
	mask := func(start, end int) {
		for i := start; i < end && i < len(masked); i++ {
			masked[i] = ' '
		}
	}
	for i := 0; i < len(line); {
		switch {
		case s.inBlockComment:
			end := strings.Index(line[i:], "*/")
			if end < 0 {
				mask(i, len(line))
				return string(masked)
			}
			mask(i, i+end+2)
			s.inBlockComment = false
			i += end + 2
		case s.inTemplate:
			end, closed := jsQuotedEnd(line, i-1, '`')
			s.inTemplate = !closed
			i = end
		case strings.HasPrefix(line[i:], "//"):
			mask(i, len(line))
			return string(masked)
		case strings.HasPrefix(line[i:], "/*") && (i == 0 || line[i-1] != '\\'):
			s.inBlockComment = true
			mask(i, i+2)
			i += 2
		case line[i] == '"' || line[i] == '\'':
			i, _ = jsQuotedEnd(line, i, line[i])
		case line[i] == '`':
			end, closed := jsQuotedEnd(line, i, '`')
			s.inTemplate = !closed
			i = end
		default:
			i++
		}
	}
	return string(masked)
}

// jsQuotedEnd returns the index just past the closing quote and whether it was found on this line.
func jsQuotedEnd(line string, start int, quote byte) (int, bool) {
	for i := start + 1; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++
		case quote:
			return i + 1, true
		}
	}
	return len(line), false
}

// jsCommentRules deliberately match COMMENT text (compiler and linter pragmas), so they read the
// raw line; every other JS rule reads the comment-masked view.
var jsCommentRules = map[string]bool{
	"ts-ts-ignore":              true,
	"ts-no-nocheck":             true,
	"ts-triple-slash-reference": true,
	"ts-ban-tslint-comment":     true,
}

func jsRuleMatches(r *rule, raw, code string) bool {
	if jsCommentRules[r.id] {
		return r.re.MatchString(raw) && !r.skip(raw)
	}
	return r.re.MatchString(code) && !r.skip(code)
}

// browserGlobalRe marks a file that runs in the browser. A bare fetch(x) there is a client-side
// request the page already controls, not a server-side fetch an attacker can point at internal
// hosts, so the SSRF rule has nothing to say about it.
var browserGlobalRe = regexp.MustCompile(`\b(document\.|window\.|navigator\.|localStorage\.|\$\(document\))`)

func browserContextFile(lines []string) bool {
	for _, line := range lines {
		if len(line) <= maxLineBytes && browserGlobalRe.MatchString(line) {
			return true
		}
	}
	return false
}

// clientComponentExts are single-file component formats that describe a rendered page. The component IS
// browser code, so it needs no sighting of a browser global: a Vue SFC reaches the DOM through its
// <template> block and its script talks to the page, and on one real repository 20 SSRF findings sat in
// .vue files purely because none of them happened to write `window.` or `document.`.
var clientComponentExts = map[string]bool{".vue": true, ".svelte": true, ".astro": true}

// scriptHostExts are server-rendered markup formats whose <script> element ships JavaScript to the page.
var scriptHostExts = map[string]bool{
	".html": true, ".htm": true, ".php": true, ".phtml": true, ".twig": true,
	".erb": true, ".jsp": true, ".ejs": true, ".hbs": true, ".handlebars": true,
}

// scriptOpenRe matches an opening <script> element.
var scriptOpenRe = regexp.MustCompile(`(?i)<script[\s>]`)

// browserScriptHost reports whether the file is markup carrying a <script> element, so the JavaScript in
// it runs in the reader's browser rather than on the server. A Blade template's extension is .php, and
// the JavaScript in its <script> block is no more server-side than a .js file's.
func browserScriptHost(ext string, lines []string) bool {
	if !scriptHostExts[ext] {
		return false
	}
	for _, line := range lines {
		if len(line) <= maxLineBytes && scriptOpenRe.MatchString(line) {
			return true
		}
	}
	return false
}

// goMainOrInitRe opens the only functions allowed to end the process. log.Fatal there is the
// documented way to stop a program; anywhere else it skips deferred cleanup in library code.
var goMainOrInitRe = regexp.MustCompile(`^\s*func\s+(?:main|init)\s*\(\s*\)\s*\{`)

// goExitFuncContext tracks whether the scan is inside func main() or func init().
type goExitFuncContext struct {
	inside bool
	depth  int
}

// advance consumes one line and reports whether that line sits inside main/init.
func (g *goExitFuncContext) advance(line string) bool {
	if !g.inside && goMainOrInitRe.MatchString(line) {
		g.inside, g.depth = true, 0
	}
	if !g.inside {
		return false
	}
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '{':
			g.depth++
		case '}':
			g.depth--
			if g.depth <= 0 {
				g.inside = false
			}
		}
	}
	return true
}
