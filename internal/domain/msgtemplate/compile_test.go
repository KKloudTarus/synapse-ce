package msgtemplate

import (
	"errors"
	"strings"
	"testing"
)

func TestCompileRejectsForbiddenConstructs(t *testing.T) {
	nested := func(n int) string {
		return strings.Repeat("{{if .title}}", n) + "x" + strings.Repeat("{{end}}", n)
	}
	cases := []struct {
		name   string
		source string
		code   Code
	}{
		{"call", `{{call .title}}`, CodeForbiddenFunction},
		{"print", `{{print .title}}`, CodeForbiddenFunction},
		{"printf", `{{printf "%s" .title}}`, CodeForbiddenFunction},
		{"println", `{{println .title}}`, CodeForbiddenFunction},
		{"index", `{{index .items 0}}`, CodeForbiddenFunction},
		{"slice", `{{slice .title 0 1}}`, CodeForbiddenFunction},
		{"len", `{{len .items}}`, CodeForbiddenFunction},
		{"html", `{{html .title}}`, CodeForbiddenFunction},
		{"js", `{{js .title}}`, CodeForbiddenFunction},
		{"urlquery", `{{urlquery .title}}`, CodeForbiddenFunction},
		{"escape function is internal", `{{msgtemplate_escape_value .title}}`, CodeForbiddenFunction},
		{"define", `{{define "x"}}{{.title}}{{end}}{{.title}}`, CodeForbiddenDefine},
		{"define recursion", `{{define "x"}}{{template "x"}}{{end}}{{template "x"}}`, CodeForbiddenDefine},
		{"block", `{{block "x" .}}{{.title}}{{end}}`, CodeForbiddenDefine},
		{"template call", `{{template "test"}}`, CodeForbiddenTemplateCall},
		{"declaration", `{{$x := .title}}{{$x}}`, CodeForbiddenDeclaration},
		{"declaration in if", `{{if $x := .title}}{{$x}}{{end}}`, CodeForbiddenDeclaration},
		{"declaration in with", `{{with $x := .title}}{{$x}}{{end}}`, CodeForbiddenDeclaration},
		{"assignment", `{{range $i, $item := .items}}{{$i = 3}}{{end}}`, CodeForbiddenAssignment},
		{"range integer", `{{range 3}}x{{end}}`, CodeInvalidRange},
		{"range scalar", `{{range .title}}x{{end}}`, CodeInvalidRange},
		{"range pipeline", `{{range .items | count}}x{{end}}`, CodeInvalidRange},
		{"range declared variable", `{{range $i, $item := .items}}{{range $item}}x{{end}}{{end}}`, CodeInvalidRange},
		{"nil", `{{eq nil .title}}`, CodeForbiddenNode},
		{"method on named value", `{{.title.Len}}`, CodeInvalidField},
		{"chain", `{{(.title).Len}}`, CodeForbiddenNode},
		{"root dot", `{{.}}`, CodeDotOutsideScope},
		{"item dot", `{{range .items}}{{.}}{{end}}`, CodeDotOutsideScope},
		{"bare root variable", `{{$}}`, CodeInvalidVariable},
		{"bare item variable", `{{range $item := .items}}{{$item}}{{end}}`, CodeInvalidVariable},
		{"unknown variable", `{{.secret}}`, CodeUnknownVariable},
		{"unknown item field", `{{range .items}}{{.host}}{{end}}`, CodeUnknownField},
		{"field on scalar", `{{with .title}}{{.severity}}{{end}}`, CodeInvalidField},
		{"list printed", `{{.items}}`, CodeListMisuse},
		{"list in condition", `{{if .items}}x{{end}}`, CodeListMisuse},
		{"list in comparison", `{{eq .items .title}}`, CodeListMisuse},
		{"scalar counted", `{{count .title}}`, CodeListMisuse},
		{"join unknown field", `{{join "secret" ", " .items}}`, CodeUnknownField},
		{"join computed field", `{{join .title ", " .items}}`, CodeUnknownField},
		{"wrong argument count", `{{upper .title .summary}}`, CodeWrongArgumentCount},
		{"niladic function argument", `{{default upper .title}}`, CodeWrongArgumentCount},
		{"non-function pipeline stage", `{{.title | .summary}}`, CodeInvalidPipeline},
		{"deep nesting", nested(MaxControlNesting + 1), CodeNestingTooDeep},
		{"range nesting", `{{range $.items}}{{range $.affected}}{{range $.affected}}x{{end}}{{end}}{{end}}`, CodeRangeNestingTooDeep},
		{"iteration product", `{{range $.items}}{{range $.big}}x{{end}}{{end}}`, CodeIterationBoundExceeded},
		{"too many nodes", strings.Repeat("{{.title}}", MaxNodes/4+1), CodeTooManyNodes},
		{"source too large", strings.Repeat("x", MaxSourceBytes+1), CodeSourceTooLarge},
		{"bidi control in source", "a" + string(rune(0x202e)) + "b", CodeForbiddenCharacter},
		{"invalid utf8", "a\xffb", CodeInvalidEncoding},
		{"parse error", `{{.title`, CodeParse},
		{"empty", ``, CodeEmptyTemplate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile("test", tc.source, testSchema())
			var tmplErr *Error
			if !errors.As(err, &tmplErr) || tmplErr.Code != tc.code {
				t.Fatalf("Compile(%.60q) error = %v, want code %s", tc.source, err, tc.code)
			}
			if !errors.Is(err, ErrInvalidTemplate) {
				t.Fatalf("error %v does not wrap ErrInvalidTemplate", err)
			}
		})
	}
}

func TestCompileAcceptsAllowedConstructs(t *testing.T) {
	cases := []string{
		`{{/* comment */}}{{.title}}`,
		`{{if eq .severity "critical"}}!{{else if eq .severity "high"}}h{{else if eq .severity "medium"}}m{{else if eq .severity "low"}}l{{else}}i{{end}}`,
		`{{with .owner}}{{.}}{{else}}nobody{{end}}`,
		`{{range $i, $item := .items}}{{$i}} {{$item.title}} {{$.title}}{{if eq $i 3}}{{break}}{{end}}{{end}}`,
		`{{range .items}}{{.title}}{{range $.affected}}{{.host}}{{end}}{{else}}none{{end}}`,
		`{{.items | join "title" ", "}} {{count .items}} {{plural (count .items) "item" "items"}}`,
		`{{.title | truncate 80 | upper}} {{severity_label .severity}} {{.owner | default "unassigned"}}`,
		`{{if and .title (not .owner) (or .summary .severity)}}{{ne .title .summary}}{{end}}`,
	}
	for _, source := range cases {
		mustCompile(t, source)
	}
}

func TestCompileRejectsInvalidSchema(t *testing.T) {
	for _, schema := range []Schema{
		{Vars: []string{"Title"}},
		{Vars: []string{"title", "title"}},
		{Vars: []string{"items"}, Lists: map[string]List{"items": {Cap: 1, Fields: []string{"a"}}}},
		{Lists: map[string]List{"items": {Cap: 0, Fields: []string{"a"}}}},
		{Lists: map[string]List{"items": {Cap: 1}}},
		{Lists: map[string]List{"items": {Cap: 1, Fields: []string{"a-b"}}}},
	} {
		if _, err := Compile("test", "x", schema); err == nil {
			t.Fatalf("schema %+v accepted", schema)
		}
	}
}

func TestCompileBoundsEvaluationCost(t *testing.T) {
	body := strings.Repeat(`{{if eq $.title "x"}}{{end}}`, 280)
	_, err := Compile("test", `{{range $.items}}{{range $.items}}`+body+`{{end}}{{end}}`, testSchema())
	var tmplErr *Error
	if !errors.As(err, &tmplErr) || tmplErr.Code != CodeCostBoundExceeded {
		t.Fatalf("err = %v, want %s", err, CodeCostBoundExceeded)
	}
	// A realistic digest stays well inside the bound.
	mustCompile(t, `{{range .items}}- {{severity_label .severity}} {{.title | truncate 120}}{{range $.affected}} {{.host}}{{end}}
{{end}}`)
}

func TestCompileRejectsDanglingEscape(t *testing.T) {
	_, err := Compile("test", `\{{.title}}`, testSchema())
	var tmplErr *Error
	if !errors.As(err, &tmplErr) || tmplErr.Code != CodeDanglingEscape {
		t.Fatalf("err = %v", err)
	}
	if got := render(t, strings.Repeat(`\`, 2)+`{{.title}}`, Data{Vars: map[string]string{"title": "*x*"}}); got != strings.Repeat(`\`, 3)+`*x\*` {
		t.Fatalf("got %q", got)
	}
}
