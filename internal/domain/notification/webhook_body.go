package notification

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Custom JSON body of a generic webhook (#1376).
//
// The body field of a webhook-family template is a JSON document whose string values may hold
// template expressions. It is never rendered as text and then parsed: the source is decoded once
// into a value tree, each string value is rendered on its own, and the tree is re-encoded with
// json.Marshal. A rendered value is therefore always one JSON string, whatever it contains, so a
// variable holding `"}`, `","admin":true`, `123`, `true` or `{"a":1}` can never change the
// structure or the type of anything in the body.
//
// The source is checked when a webhook template is saved and when it is bound:
//   - at most MaxWebhookBodyBytes, valid UTF-8, exactly one JSON object;
//   - decoded with UseNumber, so numbers keep their literal text and are never rounded;
//   - no duplicate key in any object (encoding/json would keep the last one silently);
//   - nesting at most MaxWebhookBodyDepth, at most MaxWebhookBodyLeaves leaf values;
//   - template expressions ({{ … }}) only inside string values: never in a key and never as a bare
//     value, which is not JSON anyway and is reported precisely instead of as a syntax error.
const (
	MaxWebhookBodyBytes  = 16 << 10
	MaxWebhookBodyDepth  = 8
	MaxWebhookBodyLeaves = 256
	// MaxWebhookBodyValueRunes caps one rendered string value.
	MaxWebhookBodyValueRunes = 4000
	// MaxRenderedWebhookBodyBytes caps the rendered body a driver sends.
	MaxRenderedWebhookBodyBytes = 256 << 10
	// CustomWebhookBodyHeader is set to "custom" on a request whose body is a rendered custom
	// body instead of the event envelope, so a receiver can tell the two shapes apart.
	CustomWebhookBodyHeader = "X-Synapse-Body"
)

// WebhookBodyCode is a stable reason a custom body source was refused.
type WebhookBodyCode string

const (
	WebhookBodyTooLarge          WebhookBodyCode = "body_too_large"
	WebhookBodyInvalidEncoding   WebhookBodyCode = "body_invalid_encoding"
	WebhookBodyInvalidJSON       WebhookBodyCode = "body_invalid_json"
	WebhookBodyNotObject         WebhookBodyCode = "body_not_object"
	WebhookBodyTrailingData      WebhookBodyCode = "body_trailing_data"
	WebhookBodyDuplicateKey      WebhookBodyCode = "duplicate_key"
	WebhookBodyTooDeep           WebhookBodyCode = "too_deep"
	WebhookBodyTooManyLeaves     WebhookBodyCode = "too_many_leaves"
	WebhookBodyExpressionInKey   WebhookBodyCode = "expression_in_key"
	WebhookBodyExpressionOutside WebhookBodyCode = "expression_outside_string"
	WebhookBodyRenderedTooLarge  WebhookBodyCode = "rendered_body_too_large"
)

// WebhookBodyError locates a refused custom body: a JSONPath-like path to the value ($, $.a,
// $.list[2], $["odd key"]) and, for errors found while scanning the source, a line and column. It
// never quotes a value.
type WebhookBodyError struct {
	Code   WebhookBodyCode
	Path   string
	Line   int
	Column int
	Detail string
}

func (e *WebhookBodyError) Error() string {
	var b strings.Builder
	b.WriteString("webhook body: " + string(e.Code))
	if e.Path != "" {
		b.WriteString(" at " + e.Path)
	}
	if e.Line > 0 {
		fmt.Fprintf(&b, " (line %d, column %d)", e.Line, e.Column)
	}
	if e.Detail != "" {
		b.WriteString(": " + e.Detail)
	}
	return b.String()
}

// Unwrap classifies the rejection as a validation error.
func (e *WebhookBodyError) Unwrap() error { return shared.ErrValidation }

type webhookValueKind uint8

const (
	webhookString webhookValueKind = iota + 1
	webhookNumber
	webhookBool
	webhookNull
	webhookObject
	webhookArray
)

// webhookValue is one node of a parsed body. Objects keep their members in source order.
type webhookValue struct {
	kind    webhookValueKind
	path    string
	text    string // string value, or the literal text of a number
	boolean bool
	members []webhookMember
	items   []webhookValue
}

type webhookMember struct {
	key   string
	value webhookValue
}

// WebhookBody is a parsed and structurally valid custom body source.
type WebhookBody struct{ root webhookValue }

// WebhookBodyExpression is one string value that holds template source.
type WebhookBodyExpression struct {
	Path   string
	Source string
}

// Expressions lists the string values that contain a template expression, in document order.
func (b *WebhookBody) Expressions() []WebhookBodyExpression {
	var out []WebhookBodyExpression
	var walk func(v webhookValue)
	walk = func(v webhookValue) {
		switch v.kind {
		case webhookString:
			if strings.Contains(v.text, "{{") {
				out = append(out, WebhookBodyExpression{Path: v.path, Source: v.text})
			}
		case webhookObject:
			for _, m := range v.members {
				walk(m.value)
			}
		case webhookArray:
			for _, item := range v.items {
				walk(item)
			}
		}
	}
	walk(b.root)
	return out
}

// ParseWebhookBody checks a custom body source and decodes it into a value tree.
func ParseWebhookBody(source string) (*WebhookBody, error) {
	if len(source) > MaxWebhookBodyBytes {
		return nil, &WebhookBodyError{Code: WebhookBodyTooLarge, Detail: fmt.Sprintf("the body source is limited to %d bytes", MaxWebhookBodyBytes)}
	}
	if !utf8.ValidString(source) {
		return nil, &WebhookBodyError{Code: WebhookBodyInvalidEncoding}
	}
	// Scan first: an expression outside a string makes the source invalid JSON, and the decoder's
	// syntax error would not say why.
	if line, column, found := expressionOutsideString(source); found {
		return nil, &WebhookBodyError{Code: WebhookBodyExpressionOutside, Line: line, Column: column,
			Detail: "template expressions are only allowed inside JSON string values; quote the value"}
	}
	dec := json.NewDecoder(strings.NewReader(source))
	dec.UseNumber()
	p := &webhookParser{dec: dec, source: source}
	root, err := p.value("$", 1)
	if err != nil {
		return nil, err
	}
	if root.kind != webhookObject {
		return nil, &WebhookBodyError{Code: WebhookBodyNotObject, Path: "$", Detail: "the body must be one JSON object"}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, &WebhookBodyError{Code: WebhookBodyTrailingData, Detail: "the body must hold exactly one JSON object"}
	}
	return &WebhookBody{root: root}, nil
}

type webhookParser struct {
	dec    *json.Decoder
	source string
	leaves int
}

func (p *webhookParser) syntax(path string, err error) error {
	line, column := lineColumn(p.source, int(p.dec.InputOffset()))
	detail := "invalid JSON"
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		line, column = lineColumn(p.source, int(syntaxErr.Offset))
		detail = syntaxErr.Error()
	} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		detail = "unexpected end of the body"
	}
	return &WebhookBodyError{Code: WebhookBodyInvalidJSON, Path: path, Line: line, Column: column, Detail: detail}
}

func (p *webhookParser) leaf(path string) error {
	p.leaves++
	if p.leaves > MaxWebhookBodyLeaves {
		return &WebhookBodyError{Code: WebhookBodyTooManyLeaves, Path: path, Detail: fmt.Sprintf("the body may hold at most %d values", MaxWebhookBodyLeaves)}
	}
	return nil
}

// value reads one JSON value at path; depth is the nesting level the value would open.
func (p *webhookParser) value(path string, depth int) (webhookValue, error) {
	token, err := p.dec.Token()
	if err != nil {
		return webhookValue{}, p.syntax(path, err)
	}
	switch t := token.(type) {
	case json.Delim:
		if depth > MaxWebhookBodyDepth {
			return webhookValue{}, &WebhookBodyError{Code: WebhookBodyTooDeep, Path: path, Detail: fmt.Sprintf("objects and arrays nest at most %d deep", MaxWebhookBodyDepth)}
		}
		switch t {
		case '{':
			return p.object(path, depth)
		case '[':
			return p.array(path, depth)
		}
		return webhookValue{}, p.syntax(path, fmt.Errorf("unexpected %s", t))
	case string:
		return webhookValue{kind: webhookString, path: path, text: t}, p.leaf(path)
	case json.Number:
		return webhookValue{kind: webhookNumber, path: path, text: t.String()}, p.leaf(path)
	case bool:
		return webhookValue{kind: webhookBool, path: path, boolean: t}, p.leaf(path)
	case nil:
		return webhookValue{kind: webhookNull, path: path}, p.leaf(path)
	}
	return webhookValue{}, p.syntax(path, fmt.Errorf("unexpected token"))
}

func (p *webhookParser) object(path string, depth int) (webhookValue, error) {
	out := webhookValue{kind: webhookObject, path: path, members: []webhookMember{}}
	seen := map[string]bool{}
	for p.dec.More() {
		token, err := p.dec.Token()
		if err != nil {
			return webhookValue{}, p.syntax(path, err)
		}
		key, ok := token.(string)
		if !ok {
			return webhookValue{}, p.syntax(path, fmt.Errorf("object key must be a string"))
		}
		keyPath := childPath(path, key)
		if strings.Contains(key, "{{") {
			return webhookValue{}, &WebhookBodyError{Code: WebhookBodyExpressionInKey, Path: keyPath, Detail: "object keys are literal; template expressions are only allowed in string values"}
		}
		if seen[key] {
			return webhookValue{}, &WebhookBodyError{Code: WebhookBodyDuplicateKey, Path: keyPath, Detail: "each key may appear once per object"}
		}
		seen[key] = true
		value, err := p.value(keyPath, depth+1)
		if err != nil {
			return webhookValue{}, err
		}
		out.members = append(out.members, webhookMember{key: key, value: value})
	}
	if _, err := p.dec.Token(); err != nil { // the closing brace
		return webhookValue{}, p.syntax(path, err)
	}
	if len(out.members) == 0 {
		return out, p.leaf(path)
	}
	return out, nil
}

func (p *webhookParser) array(path string, depth int) (webhookValue, error) {
	out := webhookValue{kind: webhookArray, path: path, items: []webhookValue{}}
	for i := 0; p.dec.More(); i++ {
		value, err := p.value(path+"["+strconv.Itoa(i)+"]", depth+1)
		if err != nil {
			return webhookValue{}, err
		}
		out.items = append(out.items, value)
	}
	if _, err := p.dec.Token(); err != nil { // the closing bracket
		return webhookValue{}, p.syntax(path, err)
	}
	if len(out.items) == 0 {
		return out, p.leaf(path)
	}
	return out, nil
}

// childPath appends key to path: .key for a plain identifier, ["key"] otherwise. Keys are capped
// so a path stays short.
func childPath(path, key string) string {
	plain := key != "" && len(key) <= 64
	for i, r := range key {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9')) {
			plain = false
			break
		}
	}
	if plain {
		return path + "." + key
	}
	if len(key) > 64 {
		key = key[:64]
		for !utf8.ValidString(key) {
			key = key[:len(key)-1]
		}
		key += "…"
	}
	return path + "[" + strconv.Quote(key) + "]"
}

// expressionOutsideString reports the first "{{" that is not inside a JSON string.
func expressionOutsideString(source string) (line, column int, found bool) {
	inString, escaped := false, false
	for i := 0; i < len(source); i++ {
		c := source[i]
		switch {
		case inString && escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case !inString && c == '{' && i+1 < len(source) && source[i+1] == '{':
			line, column = lineColumn(source, i)
			return line, column, true
		}
	}
	return 0, 0, false
}

// lineColumn converts a byte offset to a 1-based line and column (in runes).
func lineColumn(source string, offset int) (int, int) {
	if offset > len(source) {
		offset = len(source)
	}
	if offset < 0 {
		offset = 0
	}
	prefix := source[:offset]
	line := strings.Count(prefix, "\n") + 1
	column := utf8.RuneCountInString(prefix[strings.LastIndexByte(prefix, '\n')+1:]) + 1
	return line, column
}

// WebhookBodyTemplate is a custom body whose expression values are compiled against one event's
// variable schema. It is immutable and safe for concurrent Render calls.
type WebhookBodyTemplate struct {
	body     *WebhookBody
	compiled map[string]*msgtemplate.Template // by path
}

// WebhookBodyCompileError is an expression value the template engine refused, with its path.
type WebhookBodyCompileError struct {
	Path string
	Err  error
}

func (e *WebhookBodyCompileError) Error() string {
	return "webhook body value at " + e.Path + ": " + e.Err.Error()
}
func (e *WebhookBodyCompileError) Unwrap() error { return e.Err }

// CompileWebhookBody compiles every expression value of body with schema. A rejection is a
// *WebhookBodyCompileError wrapping the engine's *msgtemplate.Error.
func CompileWebhookBody(body *WebhookBody, schema *msgtemplate.Schema) (*WebhookBodyTemplate, error) {
	out := &WebhookBodyTemplate{body: body, compiled: map[string]*msgtemplate.Template{}}
	for _, expression := range body.Expressions() {
		compiled, err := msgtemplate.Compile("body", expression.Source, schema)
		if err != nil {
			return nil, &WebhookBodyCompileError{Path: expression.Path, Err: err}
		}
		out.compiled[expression.Path] = compiled
	}
	return out, nil
}

// Render renders every expression value with data and re-encodes the whole tree with
// json.Marshal. Literal strings, numbers, booleans and nulls are emitted as written, and object
// keys keep their order. A rendered value is plain text: the Markdown escapes the engine adds to
// interpolated values are removed, and the text becomes one JSON string.
func (t *WebhookBodyTemplate) Render(data msgtemplate.Data) ([]byte, error) {
	tree, err := t.build(t.body.root, data)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(tree)
	if err != nil {
		return nil, fmt.Errorf("encode webhook body: %w", err)
	}
	if len(encoded) > MaxRenderedWebhookBodyBytes {
		return nil, &WebhookBodyError{Code: WebhookBodyRenderedTooLarge, Detail: fmt.Sprintf("the rendered body is limited to %d bytes", MaxRenderedWebhookBodyBytes)}
	}
	return encoded, nil
}

func (t *WebhookBodyTemplate) build(v webhookValue, data msgtemplate.Data) (any, error) {
	switch v.kind {
	case webhookString:
		compiled, ok := t.compiled[v.path]
		if !ok {
			return v.text, nil
		}
		output, err := compiled.Render(data, MaxWebhookBodyValueRunes)
		if err != nil {
			return nil, &WebhookBodyCompileError{Path: v.path, Err: err}
		}
		return unescapeMarkdown(output.Text), nil
	case webhookNumber:
		return json.Number(v.text), nil
	case webhookBool:
		return v.boolean, nil
	case webhookNull:
		return nil, nil
	case webhookArray:
		items := make([]any, len(v.items))
		for i, item := range v.items {
			built, err := t.build(item, data)
			if err != nil {
				return nil, err
			}
			items[i] = built
		}
		return items, nil
	case webhookObject:
		members := make(orderedObject, len(v.members))
		for i, m := range v.members {
			built, err := t.build(m.value, data)
			if err != nil {
				return nil, err
			}
			members[i] = orderedMember{key: m.key, value: built}
		}
		return members, nil
	}
	return nil, fmt.Errorf("webhook body: unknown value at %s", v.path)
}

// orderedObject encodes an object with its keys in source order. Every key and value is encoded by
// json.Marshal, and json.Marshal validates and compacts the result again.
type orderedObject []orderedMember

type orderedMember struct {
	key   string
	value any
}

func (o orderedObject) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(m.key)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(m.value)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// unescapeMarkdown removes CommonMark backslash escapes: a backslash before ASCII punctuation is
// dropped, as a Markdown renderer would. msgtemplate escapes every interpolated value that way, and
// a webhook body is plain text, not Markdown.
func unescapeMarkdown(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && isASCIIPunctuation(s[i+1]) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isASCIIPunctuation(c byte) bool {
	return strings.IndexByte("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", c) >= 0
}

// RenderCustomWebhookBody parses, compiles and renders a custom body source in one call. The
// send-time renderer (#1365) calls it, or the three steps separately to cache the compiled form.
func RenderCustomWebhookBody(source string, schema *msgtemplate.Schema, data msgtemplate.Data) ([]byte, error) {
	body, err := ParseWebhookBody(source)
	if err != nil {
		return nil, err
	}
	compiled, err := CompileWebhookBody(body, schema)
	if err != nil {
		return nil, err
	}
	return compiled.Render(data)
}
