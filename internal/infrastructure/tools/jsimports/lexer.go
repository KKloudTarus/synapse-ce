package jsimports

import "strings"

// tokenKind identifies the lexical class of a scanned token. The lexer is deliberately coarse: it
// classifies only what import extraction needs (identifiers/keywords, string literals, punctuation) and
// skips only what cannot contain code (comments, JSX element text).
type tokenKind uint8

const (
	tokenEOF tokenKind = iota
	// tokenIdent covers identifiers, keywords and numeric literals; import extraction only ever
	// compares them against fixed keywords, so no further split is needed.
	tokenIdent
	// tokenString is a single- or double-quoted literal with its value already unescaped.
	tokenString
	// tokenTemplate is a backtick template literal. A substitution-free template carries its literal
	// value; one with `${` carries hasSubstitution and no value, and its substitution BODIES are
	// tokenized as ordinary code so a loader inside them is still seen.
	tokenTemplate
	// tokenPunct is any operator or punctuator, held verbatim (".", "(", "{", "=>", "?.", ...).
	tokenPunct
)

// token is one lexical unit with its 1-based source position.
type token struct {
	kind tokenKind
	// text is the identifier/punctuator verbatim, or the DECODED value of a string/template literal.
	text string
	// hasSubstitution marks a template literal containing `${`: its runtime value is not static, so it
	// must never be read as a literal module specifier.
	hasSubstitution bool
	// undecodedEscape marks a literal that contained an escape this lexer does not decode. Its value is
	// therefore not the runtime specifier, so it must not become a resolved module edge.
	undecodedEscape bool
	line            int
	column          int
}

// hazard is a lexically observed construct that can load a module invisibly, or a condition under which
// a load could have been missed. Each one degrades coverage: a later analyzer must not read "no edge" as
// proof of absence when any hazard is present.
type hazard struct {
	kind hazardKind
	line int
	// detail is a short, non-source-quoting label. Scanner output is sealed into judgments, so it must
	// never carry target source text (golden rule 3).
	detail string
}

type hazardKind uint8

const (
	hazardDynamicRequire hazardKind = iota
	hazardDynamicImport
	hazardEval
	hazardNewFunction
	hazardRequireContext
	hazardImportMetaGlob
	hazardModuleCreateRequire
	hazardUnsupportedLoader
	hazardMalformedSource
)

// maxFrameDepth bounds the lexer's context stack (nested JSX elements, expression containers and
// template substitutions). A hostile file of deeply nested constructs must terminate, and the stack is a
// slice rather than recursion so exceeding the bound fails loudly instead of exhausting memory.
const maxFrameDepth = 256

// loaderSignatures betray module-loading code. They are a BACKSTOP only: they are checked against JSX
// element text, which is the single remaining region this lexer skips without tokenizing. Everything that
// can contain code — template substitutions, JSX expression containers, JSX attribute expressions — is
// lexed as code instead, so the extractor's full loader vocabulary applies there.
//
// Each signature is LOADER-SHAPED — it includes the punctuation that follows the name — so ordinary
// prose does not match. A bare "require" would match the English word "required" and permanently mark
// every project with that word in its UI copy as incomplete, which would make a negative reachability
// proof impossible for the very projects the feature exists to serve.
var loaderSignatures = []string{
	"require(", "require (", "require.", "require[",
	"import(", "import (", "import \"", "import '", "import{", "import {",
	"importScripts(", "define(", "eval(", "Function(",
	"__webpack_require__", "__non_webpack_require__", "createRequire(",
	"export {", "export*", "export *",
}

// frameKind is one entry on the lexer's context stack.
type frameKind uint8

const (
	// frameJSXChildren is JSX element content: text is skipped so prose cannot open a string literal.
	frameJSXChildren frameKind = iota
	// frameJSXTag is the inside of an opening tag, where attribute values are strings or expressions.
	frameJSXTag
	// frameExpr is a brace-delimited expression region (a JSX container or a template substitution)
	// whose body is lexed as ordinary code.
	frameExpr
	// frameTemplate is a template literal with substitutions, resumed after each substitution closes.
	frameTemplate
)

type frame struct {
	kind frameKind
	// braceDepth counts nested braces inside an expression region.
	braceDepth int
}

// lexer walks a source buffer producing tokens. It never executes or evaluates anything; it only
// classifies bytes.
//
// Three lexical hazards get explicit care, because misreading any of them could swallow a real import and
// produce a SILENT MISS — the one failure this package must never have:
//
//   - regex versus division: decided from the previous significant token, and a candidate regex that
//     turns out to be division is REWOUND rather than treated as an error;
//   - JSX element text: prose containing an apostrophe ("Bob's") must not open a string literal, because
//     the matching apostrophe later in the sentence would swallow everything between them;
//   - regions that can contain code (template substitutions, JSX expression and attribute containers)
//     are LEXED, never skipped, so the extractor sees every loader inside them.
type lexer struct {
	src []byte
	pos int
	// line/col track the 1-based position of src[pos].
	line int
	col  int
	// prevSignificant is the last token emitted, used for the regex-versus-JSX-versus-division decision.
	prevSignificant token
	hasPrev         bool
	// jsxAware enables JSX element handling. It is on for every dialect except plain TypeScript, where
	// `<Foo>x` is a type assertion rather than an element.
	jsxAware bool
	// frames is the open context stack.
	frames []frame
	// hazards collects lexical coverage limitations discovered while scanning.
	hazards []hazard
	// malformed records an unterminated construct: the rest of the file cannot be trusted.
	malformed bool
}

func newLexer(src []byte, jsxAware bool) *lexer {
	return &lexer{src: src, line: 1, col: 1, jsxAware: jsxAware}
}

func (l *lexer) atEnd() bool { return l.pos >= len(l.src) }

// cursor is a saved lexer position, used to rewind a speculative scan.
type cursor struct {
	pos  int
	line int
	col  int
}

func (l *lexer) mark() cursor   { return cursor{pos: l.pos, line: l.line, col: l.col} }
func (l *lexer) reset(c cursor) { l.pos, l.line, l.col = c.pos, c.line, c.col }

func (l *lexer) addHazard(k hazardKind, line int, detail string) {
	l.hazards = append(l.hazards, hazard{kind: k, line: line, detail: detail})
}

// pushFrame adds a context frame, reporting a hazard and refusing once the depth bound is reached.
func (l *lexer) pushFrame(f frame) bool {
	if len(l.frames) >= maxFrameDepth {
		l.markMalformed(l.line, "nesting depth bound exceeded")
		return false
	}
	l.frames = append(l.frames, f)
	return true
}

func (l *lexer) popFrame() {
	if n := len(l.frames); n > 0 {
		l.frames = l.frames[:n-1]
	}
}

func (l *lexer) top() *frame {
	if n := len(l.frames); n > 0 {
		return &l.frames[n-1]
	}
	return nil
}

// advance consumes one byte, maintaining the line/column counters. CR, LF and CRLF each count as one
// line break so every reported position stays accurate.
func (l *lexer) advance() byte {
	b := l.src[l.pos]
	l.pos++
	switch {
	case b == '\r':
		if l.pos < len(l.src) && l.src[l.pos] == '\n' {
			l.pos++
		}
		l.line++
		l.col = 1
	case b == '\n':
		l.line++
		l.col = 1
	default:
		l.col++
	}
	return b
}

// isUnicodeLineSeparator reports whether the cursor sits on U+2028 or U+2029, which are ECMAScript line
// terminators encoded as three UTF-8 bytes.
func (l *lexer) isUnicodeLineSeparator() bool {
	return l.peek() == 0xE2 && l.peekAt(1) == 0x80 && (l.peekAt(2) == 0xA8 || l.peekAt(2) == 0xA9)
}

// atLineTerminator reports whether the cursor sits on any ECMAScript line terminator: LF, CR, U+2028 or
// U+2029. Testing only for LF would let a CR-only file hide the whole remainder of a line comment.
func (l *lexer) atLineTerminator() bool {
	if l.atEnd() {
		return false
	}
	b := l.peek()
	return b == '\n' || b == '\r' || l.isUnicodeLineSeparator()
}

// advanceLineTerminator consumes one line terminator of any encoding.
func (l *lexer) advanceLineTerminator() {
	if l.isUnicodeLineSeparator() {
		l.pos += 3
		l.line++
		l.col = 1
		return
	}
	l.advance()
}

// peekAt returns the byte n positions ahead of the cursor, or 0 past the end.
func (l *lexer) peekAt(n int) byte {
	if l.pos+n >= len(l.src) {
		return 0
	}
	return l.src[l.pos+n]
}

func (l *lexer) peek() byte { return l.peekAt(0) }

// next returns the next significant token.
func (l *lexer) next() token {
	for {
		// A context frame may own the cursor: JSX children skip text, a JSX tag scans attributes, and a
		// template resumes after each substitution.
		if top := l.top(); top != nil {
			switch top.kind {
			case frameJSXChildren:
				if l.atEnd() {
					l.addHazard(hazardUnsupportedLoader, l.line, "unterminated jsx element")
					l.frames = nil
					return token{kind: tokenEOF, line: l.line, column: l.col}
				}
				if t, emitted := l.stepJSXChildren(); emitted {
					return t
				}
				continue
			case frameJSXTag:
				if l.atEnd() {
					l.addHazard(hazardUnsupportedLoader, l.line, "unterminated jsx tag")
					l.frames = nil
					return token{kind: tokenEOF, line: l.line, column: l.col}
				}
				if t, emitted := l.stepJSXTag(); emitted {
					return t
				}
				continue
			case frameTemplate:
				if l.atEnd() {
					l.markMalformed(l.line, "unterminated template literal")
					return token{kind: tokenEOF, line: l.line, column: l.col}
				}
				if t, emitted := l.stepTemplate(); emitted {
					return t
				}
				continue
			}
		}

		l.skipTrivia()
		if l.atEnd() {
			return token{kind: tokenEOF, line: l.line, column: l.col}
		}

		startLine, startCol := l.line, l.col
		b := l.peek()

		switch {
		case b == '"' || b == '\'':
			value, escaped, outcome := l.readQuoted(b)
			switch outcome {
			case quotedNotAString:
				// The quote did not open a string (an apostrophe in prose). readQuoted rewound; emit the
				// quote as punctuation and carry on rather than discarding the rest of the file.
				l.advance()
				return l.emit(token{kind: tokenPunct, text: string(b), line: startLine, column: startCol})
			case quotedTruncated:
				l.markMalformed(startLine, "unterminated string literal")
				return token{kind: tokenEOF, line: startLine, column: startCol}
			}
			return l.emit(token{kind: tokenString, text: value, undecodedEscape: escaped, line: startLine, column: startCol})
		case b == '`':
			return l.startTemplate(startLine, startCol)
		case b == '\\':
			// An identifier written with a unicode escape (require) is valid JavaScript but is not
			// recognisable by the keyword matcher, so a loader could hide behind it.
			l.advance()
			l.addHazard(hazardUnsupportedLoader, startLine, "escaped identifier")
			continue
		case isIdentStart(b):
			return l.emit(token{kind: tokenIdent, text: l.readIdent(), line: startLine, column: startCol})
		case b >= '0' && b <= '9':
			return l.emit(token{kind: tokenIdent, text: l.readNumberLike(), line: startLine, column: startCol})
		case b == '<' && l.jsxAware && l.jsxElementAhead():
			l.advance() // '<'
			if !l.pushFrame(frame{kind: frameJSXTag}) {
				return token{kind: tokenEOF, line: startLine, column: startCol}
			}
			continue
		default:
			t := l.emit(token{kind: tokenPunct, text: l.readPunct(), line: startLine, column: startCol})
			l.trackExprBraces(t)
			return t
		}
	}
}

func (l *lexer) emit(t token) token {
	l.prevSignificant = t
	l.hasPrev = true
	return t
}

// emitValueLike sets the previous-token state to something that ends an expression, so a following '/'
// lexes as division and a following '<' is not read as a new JSX element.
func (l *lexer) emitValueLike() {
	l.prevSignificant = token{kind: tokenPunct, text: ")", line: l.line, column: l.col}
	l.hasPrev = true
}

// trackExprBraces maintains the brace depth of an open expression region so its closing brace is
// recognised and the enclosing JSX or template context resumes after it.
func (l *lexer) trackExprBraces(t token) {
	top := l.top()
	if top == nil || top.kind != frameExpr || t.kind != tokenPunct {
		return
	}
	switch t.text {
	case "{":
		top.braceDepth++
	case "}":
		if top.braceDepth == 0 {
			l.popFrame()
			return
		}
		top.braceDepth--
	}
}

// markMalformed records an unterminated construct and stops lexing: after it, every token would be
// unreliable. It is reached only for constructs that legitimately span lines (templates, block comments)
// or for a literal truncated at end of input — never for a quote that simply was not a string.
func (l *lexer) markMalformed(line int, detail string) {
	if !l.malformed {
		l.malformed = true
		l.addHazard(hazardMalformedSource, line, detail)
	}
	l.pos = len(l.src)
	l.frames = nil
}

// skipTrivia consumes whitespace, comments and regex literals.
func (l *lexer) skipTrivia() {
	for !l.atEnd() {
		b := l.peek()
		switch {
		case b == ' ' || b == '\t' || b == '\v' || b == '\f':
			l.advance()
		case l.atLineTerminator():
			l.advanceLineTerminator()
		case b == 0xEF && l.peekAt(1) == 0xBB && l.peekAt(2) == 0xBF:
			// UTF-8 BOM.
			l.pos += 3
			l.col++
		case b == '/' && l.peekAt(1) == '/':
			for !l.atEnd() && !l.atLineTerminator() {
				l.advance()
			}
		case b == '/' && l.peekAt(1) == '*':
			startLine := l.line
			l.advance()
			l.advance()
			closed := false
			for !l.atEnd() {
				if l.peek() == '*' && l.peekAt(1) == '/' {
					l.advance()
					l.advance()
					closed = true
					break
				}
				l.advance()
			}
			if !closed {
				l.markMalformed(startLine, "unterminated block comment")
				return
			}
		case b == '#' && l.pos == 0 && l.peekAt(1) == '!':
			// Node shebang line.
			for !l.atEnd() && !l.atLineTerminator() {
				l.advance()
			}
		case b == '<' && l.peekAt(1) == '!' && l.peekAt(2) == '-' && l.peekAt(3) == '-':
			// Annex-B HTML-like comment: a real engine treats it as a line comment, so lexing it as
			// code could invent a false edge from commented-out source.
			for !l.atEnd() && !l.atLineTerminator() {
				l.advance()
			}
		case b == '-' && l.peekAt(1) == '-' && l.peekAt(2) == '>' && l.atLineStart():
			for !l.atEnd() && !l.atLineTerminator() {
				l.advance()
			}
		case b == '/' && l.regexAllowed():
			if !l.skipRegex() {
				// Not a regex after all; leave the '/' for the caller to lex as a punctuator.
				return
			}
		default:
			return
		}
	}
}

// atLineStart reports whether only whitespace precedes the cursor on its line, which is required for the
// Annex-B closing HTML-like comment.
func (l *lexer) atLineStart() bool {
	for i := l.pos - 1; i >= 0; i-- {
		switch l.src[i] {
		case '\n', '\r':
			return true
		case ' ', '\t', '\v', '\f':
			continue
		default:
			return false
		}
	}
	return true
}

// regexAllowed reports whether a '/' at the cursor starts a regex literal rather than a division
// operator, using the previous significant token. When in doubt it answers false (division), because a
// speculative regex scan is rewound while a swallowed statement would be a silent miss.
func (l *lexer) regexAllowed() bool {
	if !l.hasPrev {
		return true
	}
	prev := l.prevSignificant
	switch prev.kind {
	case tokenString, tokenTemplate:
		return false
	case tokenIdent:
		// After a value-producing identifier '/' is division; after a keyword it starts a regex.
		return regexPrecedingKeywords[prev.text]
	case tokenPunct:
		switch prev.text {
		case ")", "]", "}", "++", "--", ">", "<":
			// These end an expression, so '/' divides. ">" and "<" also cover a JSX closing tag in a
			// file where the JSX scanner did not claim the element.
			return false
		default:
			return true
		}
	}
	return true
}

// regexPrecedingKeywords are keywords after which a '/' begins a regex literal.
var regexPrecedingKeywords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true, "new": true,
	"delete": true, "void": true, "throw": true, "case": true, "do": true, "else": true,
	"yield": true, "await": true,
}

// skipRegex speculatively consumes a regex literal including its character classes and flags. A regex
// literal cannot span a line, so hitting a line terminator (or the end of input) proves the '/' was
// division: the cursor is REWOUND and false returned, leaving the '/' to be lexed as a punctuator.
func (l *lexer) skipRegex() bool {
	start := l.mark()
	l.advance() // opening '/'
	inClass := false
	for !l.atEnd() {
		switch {
		case l.peek() == '\\':
			l.advance()
			if !l.atEnd() {
				l.advance()
			}
		case l.atLineTerminator():
			l.reset(start)
			return false
		case l.peek() == '[':
			inClass = true
			l.advance()
		case l.peek() == ']':
			inClass = false
			l.advance()
		case l.peek() == '/' && !inClass:
			l.advance()
			for !l.atEnd() && isIdentPart(l.peek()) {
				l.advance()
			}
			return true
		default:
			l.advance()
		}
	}
	l.reset(start)
	return false
}

// quotedOutcome distinguishes the three ways a quote can end, because they mean different things for
// coverage: a quote followed by a raw line terminator was never a string (an apostrophe in prose), while a
// quote that runs to the end of the file is genuinely truncated source.
type quotedOutcome uint8

const (
	quotedOK quotedOutcome = iota
	quotedNotAString
	quotedTruncated
)

// readQuoted consumes a quoted string literal and returns its decoded value plus whether it contained an
// escape this lexer does not decode.
//
// Only the escapes that can appear in a module specifier are decoded. Anything else sets the
// undecodedEscape flag so the value is never treated as a resolvable specifier: silently mis-decoding
// "\154odash" into a wrong package name would be worse than reporting the specifier as unusable.
func (l *lexer) readQuoted(quote byte) (string, bool, quotedOutcome) {
	start := l.mark()
	l.advance() // opening quote
	var sb strings.Builder
	escaped := false
	for !l.atEnd() {
		if l.atLineTerminator() {
			l.reset(start)
			return "", false, quotedNotAString
		}
		b := l.peek()
		switch b {
		case quote:
			l.advance()
			return sb.String(), escaped, quotedOK
		case '\\':
			l.advance()
			if l.atEnd() {
				l.reset(start)
				return "", false, quotedTruncated
			}
			if l.atLineTerminator() {
				// Line continuation contributes nothing to the value.
				l.advanceLineTerminator()
				continue
			}
			esc := l.advance()
			switch esc {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case 'r':
				sb.WriteByte('\r')
			case '\\', '\'', '"', '/', '`', '$':
				sb.WriteByte(esc)
			default:
				// Unicode, hex and legacy octal escapes are not decoded.
				escaped = true
				sb.WriteByte(esc)
			}
		default:
			sb.WriteByte(l.advance())
		}
	}
	l.reset(start)
	return "", false, quotedTruncated
}

// startTemplate begins a template literal at the cursor.
//
// A substitution-free template is emitted as a literal value, so `import(`pkg`)` still resolves. As soon
// as a `${` is found the template is emitted as a NON-literal token and its substitution bodies are
// tokenized as ordinary code, so a loader inside one is seen by the extractor rather than skipped.
func (l *lexer) startTemplate(startLine, startCol int) token {
	l.advance() // opening backtick
	var sb strings.Builder
	escaped := false
	for !l.atEnd() {
		b := l.peek()
		switch {
		case b == '`':
			l.advance()
			return l.emit(token{kind: tokenTemplate, text: sb.String(), undecodedEscape: escaped, line: startLine, column: startCol})
		case b == '\\':
			l.advance()
			if l.atEnd() {
				l.markMalformed(startLine, "unterminated template literal")
				return token{kind: tokenEOF, line: startLine, column: startCol}
			}
			// Template escapes are not decoded, so the value must never be used as a specifier.
			escaped = true
			sb.WriteByte(l.advance())
		case b == '$' && l.peekAt(1) == '{':
			l.advance()
			l.advance()
			if !l.pushFrame(frame{kind: frameTemplate}) {
				return token{kind: tokenEOF, line: startLine, column: startCol}
			}
			if !l.pushFrame(frame{kind: frameExpr}) {
				return token{kind: tokenEOF, line: startLine, column: startCol}
			}
			return l.emit(token{kind: tokenTemplate, hasSubstitution: true, line: startLine, column: startCol})
		default:
			sb.WriteByte(l.advance())
		}
	}
	l.markMalformed(startLine, "unterminated template literal")
	return token{kind: tokenEOF, line: startLine, column: startCol}
}

// stepTemplate resumes a template literal after one of its substitutions closed.
func (l *lexer) stepTemplate() (token, bool) {
	for !l.atEnd() {
		b := l.peek()
		switch {
		case b == '`':
			l.advance()
			l.popFrame()
			l.emitValueLike()
			return token{}, false
		case b == '\\':
			l.advance()
			if !l.atEnd() {
				l.advance()
			}
		case b == '$' && l.peekAt(1) == '{':
			l.advance()
			l.advance()
			if !l.pushFrame(frame{kind: frameExpr}) {
				return token{kind: tokenEOF}, true
			}
			return token{}, false
		default:
			l.advance()
		}
	}
	l.markMalformed(l.line, "unterminated template literal")
	return token{kind: tokenEOF}, true
}

// jsxElementAhead reports whether the '<' at the cursor opens a JSX element rather than a comparison, a
// TypeScript type-argument list, or a generic arrow function. It requires an expression position and a
// name/fragment/closing character immediately after the '<' (no space), which excludes `a < b`,
// `Map<string>` and `foo<T>()`.
func (l *lexer) jsxElementAhead() bool {
	if !l.expressionPosition() {
		return false
	}
	next := l.peekAt(1)
	if !(isIdentStart(next) || next == '>' || next == '/') {
		return false
	}
	return !l.genericArrowAhead()
}

// genericArrowAhead reports whether the '<' begins a TypeScript generic parameter list of an arrow
// function (`<T,>(x) => x`, `<T extends U>(x) => x`). Reading one as a JSX element would consume the
// function body as element text.
func (l *lexer) genericArrowAhead() bool {
	i := l.pos + 1
	// Skip the type-parameter name.
	for i < len(l.src) && isIdentPart(l.src[i]) {
		i++
	}
	if i == l.pos+1 {
		return false
	}
	for i < len(l.src) && (l.src[i] == ' ' || l.src[i] == '\t') {
		i++
	}
	if i >= len(l.src) {
		return false
	}
	switch {
	case l.src[i] == ',':
		// `<T,>` is unambiguously a generic parameter list.
		return true
	case strings.HasPrefix(string(l.src[i:]), "extends"):
		return true
	}
	// `<T>(` — a generic arrow rather than an element with no attributes.
	if l.src[i] == '>' && i+1 < len(l.src) && l.src[i+1] == '(' {
		return true
	}
	return false
}

// expressionPosition reports whether the cursor sits where an expression may begin.
func (l *lexer) expressionPosition() bool {
	if !l.hasPrev {
		return true
	}
	prev := l.prevSignificant
	switch prev.kind {
	case tokenString, tokenTemplate:
		return false
	case tokenIdent:
		return regexPrecedingKeywords[prev.text]
	case tokenPunct:
		switch prev.text {
		case ")", "]", "}", "++", "--", ">":
			return false
		default:
			return true
		}
	}
	return true
}

// stepJSXTag scans one unit of an opening tag. Attribute VALUES that are expression containers are lexed
// as code (the container's tokens reach the extractor), so a loader in an attribute is never skipped.
func (l *lexer) stepJSXTag() (token, bool) {
	// angleDepth guards a generic type argument in a tag name (`<Select<Option> ...>`) so the tag scan
	// closes on the tag's own '>' rather than the generic's.
	for !l.atEnd() {
		b := l.peek()
		switch {
		case b == '/' && l.peekAt(1) == '>':
			l.advance()
			l.advance()
			l.popFrame()
			l.emitValueLike()
			return token{}, false
		case b == '>':
			l.advance()
			l.popFrame()
			// A non-self-closing tag opens a children context.
			if !l.pushFrame(frame{kind: frameJSXChildren}) {
				return token{kind: tokenEOF}, true
			}
			return token{}, false
		case b == '<':
			// A generic type argument inside the tag name; consume it with angle matching.
			depth := 0
			for !l.atEnd() {
				if l.peek() == '<' {
					depth++
				} else if l.peek() == '>' {
					depth--
					if depth == 0 {
						l.advance()
						break
					}
				}
				l.advance()
			}
		case b == '"' || b == '\'':
			if _, _, outcome := l.readQuoted(b); outcome != quotedOK {
				l.advance()
			}
		case b == '{':
			// Lex the attribute expression as code so its tokens reach the extractor.
			line, col := l.line, l.col
			l.advance()
			if !l.pushFrame(frame{kind: frameExpr}) {
				return token{kind: tokenEOF}, true
			}
			return l.emit(token{kind: tokenPunct, text: "{", line: line, column: col}), true
		case l.isUnicodeLineSeparator():
			l.advanceLineTerminator()
		default:
			l.advance()
		}
	}
	return token{}, false
}

// stepJSXChildren consumes one unit of JSX element content: a closing tag (which pops the frame), a
// nested element, the start of an expression container, or a run of element text.
//
// Element TEXT is the only region this lexer still skips without tokenizing, so an apostrophe in prose
// cannot open a string literal whose closing apostrophe later in the sentence would swallow an expression
// container. Because skipping text could hide a real import if a comparison were misjudged as JSX, any
// skipped text containing a module-loading signature degrades coverage.
func (l *lexer) stepJSXChildren() (token, bool) {
	switch {
	case l.peek() == '<' && l.peekAt(1) == '/':
		for !l.atEnd() && l.peek() != '>' {
			l.advance()
		}
		if !l.atEnd() {
			l.advance()
		}
		l.popFrame()
		l.emitValueLike()
		return token{}, false
	case l.peek() == '<' && l.peekAt(1) == '!' && l.peekAt(2) == '-' && l.peekAt(3) == '-':
		// A JSX comment written HTML-style; consume to its terminator.
		for !l.atEnd() {
			if l.peek() == '-' && l.peekAt(1) == '-' && l.peekAt(2) == '>' {
				l.advance()
				l.advance()
				l.advance()
				break
			}
			l.advance()
		}
		return token{}, false
	case l.peek() == '<' && (isIdentStart(l.peekAt(1)) || l.peekAt(1) == '>'):
		l.advance()
		if !l.pushFrame(frame{kind: frameJSXTag}) {
			return token{kind: tokenEOF}, true
		}
		return token{}, false
	case l.peek() == '{':
		// Return the opening brace as a real token and switch to code mode: everything inside the
		// container must reach the extractor.
		line, col := l.line, l.col
		l.advance()
		if !l.pushFrame(frame{kind: frameExpr}) {
			return token{kind: tokenEOF}, true
		}
		return l.emit(token{kind: tokenPunct, text: "{", line: line, column: col}), true
	default:
		l.skipJSXText()
		return token{}, false
	}
}

// skipJSXText consumes element text up to the next '<' or '{'.
func (l *lexer) skipJSXText() {
	start := l.pos
	startLine := l.line
	for !l.atEnd() {
		b := l.peek()
		if b == '<' || b == '{' {
			break
		}
		if l.isUnicodeLineSeparator() {
			l.advanceLineTerminator()
			continue
		}
		l.advance()
	}
	l.reportSkippedLoaders(string(l.src[start:l.pos]), startLine)
}

// reportSkippedLoaders degrades coverage when a region this lexer skipped without tokenizing contains a
// module-loading signature: skipping is only safe if nothing loadable was in it.
func (l *lexer) reportSkippedLoaders(text string, line int) {
	for _, signature := range loaderSignatures {
		if strings.Contains(text, signature) {
			l.addHazard(hazardUnsupportedLoader, line, "module-loading signature inside skipped jsx text")
			return
		}
	}
}

func (l *lexer) readIdent() string {
	start := l.pos
	for !l.atEnd() && isIdentPart(l.peek()) {
		l.advance()
	}
	return string(l.src[start:l.pos])
}

// readNumberLike consumes a numeric literal loosely. Import extraction never inspects numbers; it only
// needs them to not be mistaken for identifiers or punctuation.
func (l *lexer) readNumberLike() string {
	start := l.pos
	for !l.atEnd() {
		b := l.peek()
		if isIdentPart(b) || b == '.' {
			l.advance()
			continue
		}
		break
	}
	return string(l.src[start:l.pos])
}

// multiCharPuncts are the multi-byte punctuators the extractor must see as single tokens, ordered
// LONGEST FIRST so a prefix never shadows a longer operator.
var multiCharPuncts = []string{
	"...", "===", "!==", "**=", "??=", "&&=", "||=", "?.",
	"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "**", "++", "--",
}

func (l *lexer) readPunct() string {
	remaining := l.src[l.pos:]
	for _, candidate := range multiCharPuncts {
		if len(remaining) >= len(candidate) && string(remaining[:len(candidate)]) == candidate {
			for range candidate {
				l.advance()
			}
			return candidate
		}
	}
	return string(l.advance())
}

func isIdentStart(b byte) bool {
	return b == '_' || b == '$' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b >= 0x80
}

func isIdentPart(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}
