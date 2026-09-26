package msgtemplate

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzCompileRender(f *testing.F) {
	for _, seed := range []string{
		`{{.title}}`,
		`{{range $i, $x := .items}}{{$x.title}}{{end}}`,
		`{{if eq .severity "critical"}}{{.title | upper | truncate 10}}{{end}}`,
		`{{with .owner}}{{.}}{{end}}{{count .items}}`,
		`{{define "x"}}{{end}}`,
		`{{range 3}}{{end}}`,
		`{{call .title}}`,
	} {
		f.Add(seed, "[x](https://evil.example) <!channel>", 50)
	}
	f.Fuzz(func(t *testing.T, source, value string, limit int) {
		tmpl, err := Compile("fuzz", source, testSchema())
		if err != nil {
			return
		}
		limit = 1 + abs(limit)%200
		data := Data{
			Vars:  map[string]string{"title": value, "severity": value, "summary": value, "count_new": value, "owner": value},
			Lists: map[string][]map[string]string{"items": {{"title": value, "severity": value}}, "affected": {{"host": value}}},
		}
		out, err := tmpl.Render(data, limit)
		if err != nil {
			// Static checks leave only runtime values (a non-numeric count for plural) as a cause.
			var tmplErr *Error
			if !errors.As(err, &tmplErr) || tmplErr.Code != CodeInvalidArgument {
				t.Fatalf("compiled template failed to render: %v", err)
			}
			return
		}
		if n := utf8.RuneCountInString(out.Text); n > limit {
			t.Fatalf("output has %d runes, limit %d", n, limit)
		}
		if !utf8.ValidString(out.Text) {
			t.Fatalf("output is not valid UTF-8")
		}
	})
}

func FuzzEscapedValue(f *testing.F) {
	for _, seed := range []string{"[a](b)", "- x", "12. x", "<!here>", "a\u202eb", "`x`", "\\*"} {
		f.Add(seed)
	}
	tmpl, err := Compile("fuzz", "{{.title}}", testSchema())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, value string) {
		out, err := tmpl.Render(Data{Vars: map[string]string{"title": value}}, MaxOutputRunes)
		if err != nil {
			t.Fatal(err)
		}
		if out.Truncated {
			return
		}
		escaped := false
		for i, r := range out.Text {
			if r != ' ' && forbiddenRune(r) {
				t.Fatalf("forbidden rune %U at %d", r, i)
			}
			if !escaped && r < utf8.RuneSelf && strings.ContainsRune(inlineSpecial, r) && r != '\\' {
				t.Fatalf("unescaped %q at %d in %q", r, i, out.Text)
			}
			escaped = !escaped && r == '\\'
		}
		if escaped {
			t.Fatalf("dangling escape in %q", out.Text)
		}
	})
}

func abs(n int) int {
	if n < 0 {
		if n == -n {
			return 0
		}
		return -n
	}
	return n
}
