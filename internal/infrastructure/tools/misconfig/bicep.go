package misconfig

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Bicep is Azure's DSL that transpiles to an ARM deployment template. Compiled Bicep (ARM JSON) is
// already covered by scanARM; this scanner covers RAW .bicep source, which competitors (Checkov, Trivy)
// scan directly. Rather than duplicate the Azure ruleset, it parses each `resource` declaration into the
// same armResource / yaml.Node shape scanARM builds and runs the identical scanResource checks, so a Bicep
// storage account and its compiled ARM twin produce the same findings under the same rule ids.
//
// The load-bearing soundness rule mirrors scanARM: a value that is not a plain literal (a parameter or
// variable reference, a function call, an interpolated string, a ternary) is represented as a dynamic
// sentinel that armExpression treats as unknown, so a dynamic value NEVER yields an insecure-literal
// finding. A construct the parser cannot model (a resource loop, a child resource, a module) is skipped,
// which loses coverage but never invents a finding. Parsing is text-only and bounded.

const (
	maxBicepBytes     = 4 << 20 // guard: files above this are not parsed (scanner already caps at 5 MiB)
	maxBicepDepth     = 64      // object/array nesting cap, matches maxARMDepth
	maxBicepResources = 10000   // resource-declaration cap, matches maxARMResources
)

// bicepExprSentinel is the scalar value stored for any non-literal Bicep value. armExpression reports it
// as a dynamic expression (it is bracket-wrapped), so every ARM check that guards on armExpression treats
// it as unknown and emits no insecure-literal finding.
const bicepExprSentinel = "[bicep-expr]"

// scanBicep parses a .bicep file and returns Azure misconfiguration findings using the ARM rule set.
func scanBicep(rel string, data []byte) []ports.MisconfigRawFinding {
	if len(data) == 0 || len(data) > maxBicepBytes {
		return nil
	}
	p := &bicepParser{src: string(data), line: 1}
	resources := p.parseResources()
	if len(resources) == 0 {
		return nil
	}
	s := &armScanner{rel: rel, source: string(data), ruleCount: make(map[string]int)}
	s.resources = resources
	for _, res := range resources {
		s.scanResource(res)
	}
	return s.findings
}

// bicepParser is a bounded recursive-descent reader over Bicep source. It tracks line numbers so a finding
// points at the offending line, and it never executes or resolves anything.
type bicepParser struct {
	src  string
	pos  int
	line int
}

// parseResources scans the file for top-level `resource <symbol> '<type>@<api>' = { ... }` declarations
// and returns one armResource each. It deliberately handles only the object-body form (optionally behind a
// `= if (cond)` guard); a resource loop (`= [for ...]`) or an `existing` reference is skipped.
func (p *bicepParser) parseResources() []armResource {
	var out []armResource
	for p.pos < len(p.src) && len(out) < maxBicepResources {
		if !p.seekKeyword("resource") {
			break
		}
		res, ok := p.parseResourceDecl()
		if ok {
			out = append(out, res)
		}
	}
	return out
}

// seekKeyword advances pos to just past the next occurrence of the bare keyword `word` (bounded by
// non-identifier characters and not inside a string or comment), returning false at EOF. It skips comments
// and string literals so a `resource` inside a comment or a string is not mistaken for a declaration.
func (p *bicepParser) seekKeyword(word string) bool {
	for p.pos < len(p.src) {
		if p.skipTriviaOnce() {
			continue
		}
		c := p.src[p.pos]
		if c == '\'' {
			p.consumeString() // skip a string literal wholesale
			continue
		}
		if isBicepIdentStart(c) {
			start := p.pos
			ident := p.readIdent()
			if ident == word && p.boundaryBefore(start) {
				return true
			}
			continue
		}
		p.advance(1)
	}
	return false
}

// boundaryBefore reports whether the character before start is not an identifier character, so `resource`
// is a keyword and not the tail of another identifier. start is always the beginning of a read identifier.
func (p *bicepParser) boundaryBefore(start int) bool {
	if start == 0 {
		return true
	}
	return !isBicepIdentPart(p.src[start-1])
}

// parseResourceDecl parses the remainder of a `resource` declaration after the keyword was consumed:
// `<symbol> '<type>@<api>' [existing] = <body>`. It returns ok=false for a form it does not model.
func (p *bicepParser) parseResourceDecl() (armResource, bool) {
	p.skipTrivia()
	if !isBicepIdentStart(p.peek()) {
		return armResource{}, false
	}
	p.readIdent() // symbolic name, unused
	p.skipTrivia()
	if p.peek() != '\'' {
		return armResource{}, false
	}
	typeLine := p.line
	typeToken, ok := p.consumeString()
	if !ok || strings.Contains(typeToken, bicepInterpMarker) {
		return armResource{}, false // a computed resource type cannot be keyed to a rule
	}
	typ, apiVersion := splitBicepType(typeToken)
	p.skipTrivia()
	// An `existing` reference declares no new resource; skip to its body and drop it.
	if isBicepIdentStart(p.peek()) {
		if kw := p.readIdent(); kw == "existing" {
			p.skipToBodyAndSkip()
			return armResource{}, false
		}
		// Any other keyword here is unexpected; bail out of this declaration.
		return armResource{}, false
	}
	if p.peek() != '=' {
		return armResource{}, false
	}
	p.advance(1) // '='
	p.skipTrivia()
	// Optional `if (cond)` guard before the body object.
	if isBicepIdentStart(p.peek()) {
		if kw := p.readIdent(); kw == "if" {
			p.skipParenGroup()
			p.skipTrivia()
		} else {
			return armResource{}, false
		}
	}
	if p.peek() != '{' {
		// A resource loop (`[for ...]`) or another non-object body: not modeled, skip it.
		return armResource{}, false
	}
	bodyLine := typeLine
	body := p.parseObject(0)
	if body == nil {
		return armResource{}, false
	}
	res := armResource{
		node:       body,
		properties: mapValue(body, "properties"),
		identity:   mapValue(body, "identity"),
		tags:       mapValue(body, "tags"),
		dependsOn:  mapValue(body, "dependsOn"),
		typ:        strings.ToLower(typ),
		apiVersion: apiVersion,
		line:       bodyLine,
	}
	res.name, _ = armLiteral(mapValue(body, "name"))
	res.location, _ = armLiteral(mapValue(body, "location"))
	return res, true
}

// splitBicepType splits `Microsoft.Storage/storageAccounts@2021-09-01` into the resource type and API
// version on the LAST '@'. A token with no '@' yields an empty API version.
func splitBicepType(token string) (typ, apiVersion string) {
	if i := strings.LastIndexByte(token, '@'); i >= 0 {
		return token[:i], token[i+1:]
	}
	return token, ""
}

// parseObject parses a `{ key: value ... }` object into a MappingNode. Properties are separated by
// newlines or commas. A computed or non-identifier key is skipped along with its value.
func (p *bicepParser) parseObject(depth int) *yaml.Node {
	if depth > maxBicepDepth {
		p.skipBalanced('{', '}')
		return nil
	}
	if p.peek() != '{' {
		return nil
	}
	line := p.line
	p.advance(1) // '{'
	node := &yaml.Node{Kind: yaml.MappingNode, Line: line}
	for iter := 0; p.pos < len(p.src) && iter <= len(p.src); iter++ {
		p.skipSeparators()
		if p.peek() == '}' {
			p.advance(1)
			return node
		}
		if p.pos >= len(p.src) {
			break
		}
		keyLine := p.line
		var key string
		switch {
		case isBicepIdentStart(p.peek()):
			key = p.readIdent()
		case p.peek() == '\'':
			tok, ok := p.consumeString()
			if !ok || strings.Contains(tok, bicepInterpMarker) {
				// Computed key: skip its value, keep parsing the object.
				p.skipTrivia()
				if p.peek() == ':' {
					p.advance(1)
					p.skipTrivia()
					p.skipValue(depth + 1)
				}
				continue
			}
			key = tok
		default:
			// Unexpected token; skip it to make progress.
			p.advance(1)
			continue
		}
		p.skipTrivia()
		// A nested child resource (`resource <sym> ... = { ... }`) is not a property. Skip the whole child
		// declaration so its keys are not merged into the parent object, which would desync the parse.
		if key == "resource" && p.peek() != ':' {
			p.skipNestedResource()
			continue
		}
		if p.peek() != ':' {
			continue
		}
		p.advance(1) // ':'
		p.skipTrivia()
		value := p.parseValue(depth + 1)
		if value == nil {
			continue
		}
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: key, Line: keyLine},
			value)
	}
	return node
}

// parseArray parses a `[ value, value ... ]` array into a SequenceNode. A loop comprehension (`[for ...]`)
// is not modeled: it is skipped and reported as a dynamic sentinel so no element-level rule runs on it.
func (p *bicepParser) parseArray(depth int) *yaml.Node {
	if depth > maxBicepDepth {
		p.skipBalanced('[', ']')
		return p.sentinel()
	}
	if p.peek() != '[' {
		return nil
	}
	line := p.line
	// Detect a `[for ...]` comprehension: skip it entirely and treat the value as dynamic.
	save, saveLine := p.pos, p.line
	p.advance(1)
	p.skipTrivia()
	if isBicepIdentStart(p.peek()) {
		if kw := p.readIdent(); kw == "for" {
			p.pos, p.line = save, saveLine
			p.skipBalanced('[', ']')
			return p.sentinel()
		}
	}
	p.pos, p.line = save, saveLine

	p.advance(1) // '['
	node := &yaml.Node{Kind: yaml.SequenceNode, Line: line}
	for iter := 0; p.pos < len(p.src) && iter <= len(p.src); iter++ {
		p.skipSeparators()
		if p.peek() == ']' {
			p.advance(1)
			return node
		}
		if p.pos >= len(p.src) {
			break
		}
		item := p.parseValue(depth + 1)
		if item == nil {
			break
		}
		node.Content = append(node.Content, item)
	}
	return node
}

// parseValue dispatches on the first non-trivia character to parse one Bicep value into a yaml.Node. A
// value that is not a plain object, array, string, number, or boolean/null literal is consumed as an
// expression and returned as the dynamic sentinel.
func (p *bicepParser) parseValue(depth int) *yaml.Node {
	p.skipTrivia()
	c := p.peek()
	switch {
	case c == '{':
		return p.parseObject(depth)
	case c == '[':
		return p.parseArray(depth)
	case c == '\'':
		line := p.line
		tok, ok := p.consumeString()
		if !ok {
			// An unterminated string is not a plain literal (it ran to a newline/EOF): treat as unknown so a
			// malformed value never produces an insecure-literal finding.
			return p.sentinelAt(line)
		}
		p.skipInlineTrivia()
		if strings.Contains(tok, bicepInterpMarker) || !p.atValueEnd() {
			// An interpolated string, or a string that is the HEAD of an expression ('a' + b, 'a' == x ? ...),
			// is a dynamic value. Consume the remainder of the expression and report it as unknown.
			p.consumeExpr(depth)
			return p.sentinelAt(line)
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Value: tok, Line: line}
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumberOrExpr(depth)
	case isBicepIdentStart(c):
		return p.parseIdentValue(depth)
	default:
		// A structural terminator or EOF here is not a value; returning nil lets the caller close the
		// container instead of spinning (consumeExpr would not advance past a terminator).
		if c == 0 || c == ',' || c == '}' || c == ']' || c == ')' {
			return nil
		}
		p.consumeExpr(depth)
		return p.sentinel()
	}
}

// parseIdentValue handles a value that begins with an identifier: the literals true/false/null are kept as
// scalars; anything else (a variable/parameter reference, a function call, member access, a ternary) is a
// dynamic expression and becomes the sentinel.
func (p *bicepParser) parseIdentValue(depth int) *yaml.Node {
	line := p.line
	ident := p.readIdent()
	// Look past the identifier: a bare true/false/null (not followed by '.', '(', '[', or an operator that
	// would make it part of a larger expression) is a literal.
	p.skipInlineTrivia()
	isBare := p.atValueEnd()
	if isBare && (ident == "true" || ident == "false" || ident == "null") {
		if ident == "null" {
			return &yaml.Node{Kind: yaml.ScalarNode, Value: "", Tag: "!!null", Line: line}
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Value: ident, Line: line}
	}
	// Not a bare literal: the identifier is the head of an expression. Its remainder starts at the current
	// position, so consume it so the scanner sees a single dynamic value.
	p.consumeExpr(depth)
	return p.sentinelAt(line)
}

// parseNumberOrExpr reads a numeric literal, unless it is immediately part of a larger expression, in
// which case the whole expression is consumed and the sentinel returned.
func (p *bicepParser) parseNumberOrExpr(depth int) *yaml.Node {
	line := p.line
	start := p.pos
	if p.peek() == '-' {
		p.advance(1)
	}
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if (c >= '0' && c <= '9') || c == '.' {
			p.advance(1)
			continue
		}
		break
	}
	numText := p.src[start:p.pos]
	p.skipInlineTrivia()
	if p.atValueEnd() {
		return &yaml.Node{Kind: yaml.ScalarNode, Value: numText, Line: line}
	}
	// Number is part of a larger expression (e.g. `1 + n`): consume and report dynamic.
	p.consumeExpr(depth)
	return p.sentinelAt(line)
}

// consumeExpr consumes an expression value up to the value terminator: a newline, comma, or a closing
// brace/bracket at the current nesting level, or EOF. It tracks (), [], {} nesting so a multi-line
// parenthesized expression or an inline object/array inside the expression is consumed whole. It never
// consumes the terminator itself.
func (p *bicepParser) consumeExpr(depth int) {
	nest := 0
	guard := 0
	for p.pos < len(p.src) {
		guard++
		if guard > len(p.src)+1 {
			return
		}
		c := p.src[p.pos]
		switch c {
		case '/':
			if p.skipTriviaOnce() { // a comment inside the expression
				continue
			}
			p.advance(1)
			continue
		case '\'':
			p.consumeString()
			continue
		case '(', '[', '{':
			nest++
			p.advance(1)
			continue
		case ')', ']', '}':
			if nest == 0 {
				return // a closer belonging to the enclosing container
			}
			nest--
			p.advance(1)
			continue
		case '\n', '\r':
			if nest == 0 {
				return
			}
			p.advance(1)
			continue
		case ',':
			if nest == 0 {
				return
			}
			p.advance(1)
			continue
		default:
			p.advance(1)
		}
	}
}

// skipValue consumes and discards a value (used for a computed-key property whose value we do not keep).
func (p *bicepParser) skipValue(depth int) {
	switch p.peek() {
	case '{':
		p.skipBalanced('{', '}')
	case '[':
		p.skipBalanced('[', ']')
	case '\'':
		p.consumeString()
	default:
		p.consumeExpr(depth)
	}
}

// --- low-level scanning helpers ---

const bicepInterpMarker = "\x00interp\x00" // internal marker: consumeString injects it for a `${...}` span

func (p *bicepParser) peek() byte {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

// advance moves pos forward by n bytes, counting newlines so line stays accurate.
func (p *bicepParser) advance(n int) {
	for i := 0; i < n && p.pos < len(p.src); i++ {
		if p.src[p.pos] == '\n' {
			p.line++
		}
		p.pos++
	}
}

func (p *bicepParser) readIdent() string {
	start := p.pos
	for p.pos < len(p.src) && isBicepIdentPart(p.src[p.pos]) {
		p.pos++
	}
	return p.src[start:p.pos]
}

// consumeString consumes a single-quoted Bicep string starting at the current `'`, honoring `\` escapes,
// and returns its content with each `${...}` interpolation replaced by an internal marker so the caller
// can tell an interpolated (dynamic) string from a plain literal. The opening and closing quotes are
// consumed. Multi-line strings (''' ... ''') are consumed but reported as interpolated (dynamic).
func (p *bicepParser) consumeString() (string, bool) {
	if p.peek() != '\'' {
		return "", false
	}
	// Triple-quoted multi-line string.
	if strings.HasPrefix(p.src[p.pos:], "'''") {
		p.advance(3)
		if idx := strings.Index(p.src[p.pos:], "'''"); idx >= 0 {
			p.advance(idx + 3)
		} else {
			p.advance(len(p.src) - p.pos)
		}
		return bicepInterpMarker, true // treat multi-line content as dynamic
	}
	p.advance(1) // opening quote
	var sb strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch c {
		case '\\':
			p.advance(2) // escaped char, keep it opaque
			sb.WriteByte('.')
			continue
		case '\'':
			p.advance(1) // closing quote
			return sb.String(), true
		case '$':
			if p.pos+1 < len(p.src) && p.src[p.pos+1] == '{' {
				p.advance(2)
				p.skipBalancedInner('{', '}') // consume the interpolation expression
				sb.WriteString(bicepInterpMarker)
				continue
			}
			p.advance(1)
			sb.WriteByte('$')
		case '\n':
			// An unterminated single-line string: stop at the newline and report NOT terminated, so the value
			// is treated as unknown rather than as a plain literal.
			return sb.String(), false
		default:
			p.advance(1)
			sb.WriteByte(c)
		}
	}
	return sb.String(), false // reached EOF without a closing quote
}

// atValueEnd reports whether the current position is a value terminator: a newline, comma, closing brace or
// bracket, closing paren, or EOF. A value followed by anything else (an operator, member access, index) is
// the head of an expression, i.e. dynamic.
func (p *bicepParser) atValueEnd() bool {
	c := p.peek()
	return c == 0 || c == '\n' || c == '\r' || c == ',' || c == '}' || c == ']' || c == ')'
}

// skipNestedResource skips a child `resource <sym> <type> [existing] = [if (cond)] <body>` declaration
// nested inside a parent resource body. Nested resources are not modeled; skipping the whole declaration up
// to and including its body keeps the parent object parse in sync instead of merging the child's keys into
// it. The body is the first `{` or `[` at PAREN-DEPTH ZERO: comments and strings are skipped, and a `{`/`[`
// inside a pre-body condition (`if (arr[0])`) or a comment is not mistaken for the body.
func (p *bicepParser) skipNestedResource() {
	parenDepth := 0
	for iter := 0; p.pos < len(p.src) && iter <= len(p.src); iter++ {
		if p.skipTriviaOnce() { // whitespace, newlines, and comments
			continue
		}
		switch p.peek() {
		case '\'':
			p.consumeString()
		case '(':
			parenDepth++
			p.advance(1)
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
			p.advance(1)
		case '{':
			if parenDepth == 0 {
				p.skipBalanced('{', '}')
				return
			}
			p.advance(1)
		case '[':
			if parenDepth == 0 {
				p.skipBalanced('[', ']')
				return
			}
			p.advance(1)
		case '}':
			if parenDepth == 0 {
				return // the parent's close reached before a child body (malformed); let the parent handle it
			}
			p.advance(1)
		default:
			p.advance(1)
		}
	}
}

// skipBalancedInner consumes up to and including the matching close of an already-opened open/close pair
// (the opener was already consumed). Nested pairs and inner strings are respected.
func (p *bicepParser) skipBalancedInner(open, close byte) {
	nest := 1
	for p.pos < len(p.src) {
		// A comment or string can contain unbalanced open/close bytes; skip them so they do not miscount the
		// nesting and over-skip past the real close (which would drop a following parent property).
		if p.skipCommentOnce() {
			continue
		}
		c := p.src[p.pos]
		if c == '\'' {
			p.consumeString()
			continue
		}
		if c == open {
			nest++
		} else if c == close {
			nest--
			if nest == 0 {
				p.advance(1)
				return
			}
		}
		p.advance(1)
	}
}

// skipBalanced consumes a balanced open/close group starting at the current opener (which must match
// open), including the closer. Strings and comments inside are respected.
func (p *bicepParser) skipBalanced(open, close byte) {
	if p.peek() != open {
		return
	}
	p.advance(1)
	p.skipBalancedInner(open, close)
}

// skipParenGroup skips a `( ... )` group starting at the current `(`.
func (p *bicepParser) skipParenGroup() {
	p.skipTrivia()
	if p.peek() == '(' {
		p.skipBalanced('(', ')')
	}
}

// skipToBodyAndSkip advances to the next `{` at top level and skips its balanced body (used to discard an
// `existing` resource's body).
func (p *bicepParser) skipToBodyAndSkip() {
	for p.pos < len(p.src) {
		if p.skipTriviaOnce() {
			continue
		}
		c := p.peek()
		if c == '{' {
			p.skipBalanced('{', '}')
			return
		}
		if c == '\'' {
			p.consumeString()
			continue
		}
		p.advance(1)
	}
}

// skipTrivia skips whitespace, newlines, and comments.
func (p *bicepParser) skipTrivia() {
	for p.skipTriviaOnce() {
	}
}

// skipInlineTrivia skips spaces, tabs, and comments but NOT newlines, so a value terminator (the newline)
// is preserved for the caller.
func (p *bicepParser) skipInlineTrivia() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' {
			p.pos++
			continue
		}
		if c == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '*' {
			p.skipBlockComment()
			continue
		}
		if c == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '/' {
			// a line comment ends the line; do not cross the newline here
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		break
	}
}

// skipSeparators skips whitespace, newlines, comments, and commas between object properties or array
// elements.
func (p *bicepParser) skipSeparators() {
	for {
		if p.skipTriviaOnce() {
			continue
		}
		if p.peek() == ',' {
			p.advance(1)
			continue
		}
		break
	}
}

// skipTriviaOnce skips a single run of whitespace/newline, or one comment, returning true if it advanced.
func (p *bicepParser) skipTriviaOnce() bool {
	if p.pos >= len(p.src) {
		return false
	}
	c := p.src[p.pos]
	if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
		p.advance(1)
		return true
	}
	return p.skipCommentOnce()
}

// skipCommentOnce skips a single // line comment or /* */ block comment at the current position, returning
// true if it advanced. It is shared by trivia-skipping and balanced-skipping so a comment's contents (which
// may contain unbalanced braces, brackets, or quotes) are never interpreted as structure.
func (p *bicepParser) skipCommentOnce() bool {
	if p.pos+1 >= len(p.src) || p.src[p.pos] != '/' {
		return false
	}
	if p.src[p.pos+1] == '/' {
		for p.pos < len(p.src) && p.src[p.pos] != '\n' {
			p.pos++
		}
		return true
	}
	if p.src[p.pos+1] == '*' {
		p.skipBlockComment()
		return true
	}
	return false
}

func (p *bicepParser) skipBlockComment() {
	p.advance(2) // '/*'
	if idx := strings.Index(p.src[p.pos:], "*/"); idx >= 0 {
		p.advance(idx + 2)
		return
	}
	p.advance(len(p.src) - p.pos)
}

func (p *bicepParser) sentinel() *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Value: bicepExprSentinel, Line: p.line}
}

func (p *bicepParser) sentinelAt(line int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Value: bicepExprSentinel, Line: line}
}

func isBicepIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isBicepIdentPart(c byte) bool {
	return isBicepIdentStart(c) || (c >= '0' && c <= '9')
}
