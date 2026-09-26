package msgtemplate

import (
	"strings"
	"text/template"
	"unicode/utf8"
)

// Template is a validated, immutable, reusable template. It is safe for concurrent Render calls.
type Template struct {
	schema compiledSchema
	tmpl   *template.Template
}

// Compile parses and validates source against schema. An accepted template references only
// declared variables and allowlisted functions, passes the type check, and stays within the static
// bounds in limits.go.
func Compile(name, source string, schema Schema) (*Template, error) {
	compiled, err := compileSchema(schema)
	if err != nil {
		return nil, err
	}
	if err := checkName(name); err != nil {
		return nil, err
	}
	if err := checkSource(source); err != nil {
		return nil, err
	}
	tmpl, err := parseSource(name, source)
	if err != nil {
		return nil, err
	}
	v := newValidator(source, compiled)
	if err := v.list(tmpl.Root, scope{}); err != nil {
		return nil, err
	}
	escapeOutputs(tmpl.Tree, tmpl.Root)
	return &Template{schema: compiled, tmpl: tmpl}, nil
}

func checkName(name string) error {
	if name == "" || len(name) > maxNameLength || strings.ContainsFunc(name, forbiddenRune) {
		return invalid(CodeInvalidName, 0, "")
	}
	return nil
}

// checkSource rejects oversized, malformed or invisible-character source before the parser runs.
// Tab, CR and LF are allowed in source; every other forbidden rune is not.
func checkSource(source string) error {
	if len(source) > MaxSourceBytes {
		return invalid(CodeSourceTooLarge, 0, "")
	}
	if !utf8.ValidString(source) {
		return invalid(CodeInvalidEncoding, 0, "")
	}
	offset := strings.IndexFunc(source, func(r rune) bool {
		return r != '\n' && r != '\r' && r != '\t' && forbiddenRune(r)
	})
	if offset >= 0 {
		return invalid(CodeForbiddenCharacter, lineOf(source, offset), "")
	}
	return nil
}

// parseSource builds the text/template tree and rejects anything that defines more than the one
// template being compiled (define, block).
func parseSource(name, source string) (*template.Template, error) {
	tmpl, err := template.New(name).Option("missingkey=error").Funcs(funcMap()).Parse(source)
	if err != nil {
		return nil, invalid(CodeParse, 0, strings.TrimPrefix(err.Error(), "template: "))
	}
	for _, associated := range tmpl.Templates() {
		if associated != tmpl {
			return nil, invalid(CodeForbiddenDefine, 0, associated.Name())
		}
	}
	if tmpl.Tree == nil || tmpl.Root == nil || len(tmpl.Root.Nodes) == 0 {
		return nil, invalid(CodeEmptyTemplate, 0, "")
	}
	return tmpl, nil
}
