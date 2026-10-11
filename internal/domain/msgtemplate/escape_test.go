package msgtemplate

import (
	"strings"
	"testing"
)

// unescape reverses EscapeMarkdown the way a CommonMark reader does: a backslash before ASCII
// punctuation yields the punctuation.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x5c && i+1 < len(s) && strings.IndexByte(asciiPunctuation, s[i+1]) >= 0 {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// assertEscaped fails unless every ASCII punctuation character in s is escaped.
func assertEscaped(t *testing.T, s string) {
	t.Helper()
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(asciiPunctuation, s[i]) < 0 {
			continue
		}
		if s[i] != 0x5c || i+1 >= len(s) || strings.IndexByte(asciiPunctuation, s[i+1]) < 0 {
			t.Fatalf("unescaped %q at %d in %q", s[i], i, s)
		}
		i++
	}
}

func TestEscapeMarkdownIsLosslessAndComplete(t *testing.T) {
	for _, value := range []string{
		"plain text", "Lỗi nghiêm trọng", "CVE-2024-1234", "1.2.3", "a & b",
		"[Reset password](https://evil.example)", "<!channel> @everyone", "**bold** _i_ `code` ~s~",
		"# h", "===", "---", "> quote", "1. item", "1) item", "+ item", "| a | b |",
		"https://evil.example/x", "www.evil.example", "a@b.example", "&lt;b&gt;", "&#x2a;x",
		`a\b`, `x\`, `\*`, "",
	} {
		escaped := EscapeMarkdown(value)
		assertEscaped(t, escaped)
		if got := unescape(escaped); got != value {
			t.Fatalf("unescape(EscapeMarkdown(%q)) = %q", value, got)
		}
	}
}

func TestEscapeMarkdownDropsLeadingSpaces(t *testing.T) {
	for value, want := range map[string]string{
		"    indented code": "indented code",
		"  - item":          "- item",
		"x  y":              "x  y",
	} {
		if got := unescape(EscapeMarkdown(value)); got != want {
			t.Fatalf("EscapeMarkdown(%q) reads %q, want %q", value, got, want)
		}
	}
}

func TestRenderKeepsLiteralMarkupAndUnicode(t *testing.T) {
	vi := "L" + string(rune(0x1ed7)) + "i nghi" + string(rune(0x00ea)) + "m tr" + string(rune(0x1ecd)) + "ng"
	got := render(t, "**Critical** {{.title}}\n- first", Data{Vars: map[string]string{"title": vi}})
	if want := "**Critical** " + vi + "\n- first"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// escapePayload holds markup in every syntax class; none of it may reach the output unescaped.
const escapePayload = "[x](https://evil) *b* `c` <!here> @everyone"

func TestEveryOutputPositionIsEscaped(t *testing.T) {
	data := Data{
		Vars: map[string]string{"title": escapePayload, "owner": escapePayload},
		Lists: map[string][]map[string]string{
			"items":    {{"title": escapePayload}},
			"affected": {{"host": escapePayload}},
		},
	}
	empty := Data{Vars: data.Vars}
	cases := []struct {
		name, source string
		data         Data
	}{
		{"root", `{{.title}}`, data},
		{"if body", `{{if .title}}{{.title}}{{end}}`, data},
		{"if else", `{{if .summary}}x{{else}}{{.title}}{{end}}`, data},
		{"else-if body", `{{if .summary}}x{{else if .title}}{{.title}}{{end}}`, data},
		{"with body", `{{with .title}}{{.}}{{end}}`, data},
		{"with else", `{{with .summary}}x{{else}}{{.title}}{{end}}`, data},
		{"range body", `{{range .items}}{{.title}}{{end}}`, data},
		{"range variable", `{{range $i, $x := .items}}{{$x.title}}{{end}}`, data},
		{"range else", `{{range .items}}x{{else}}{{.title}}{{end}}`, empty},
		{"nested range", `{{range .items}}{{range $.affected}}{{.host}}{{end}}{{end}}`, data},
		{"root from range", `{{range .items}}{{$.owner}}{{end}}`, data},
		{"through functions", `{{.title | truncate 200 | default "x"}}`, data},
		{"through join", `{{join "title" " " .items}}`, data},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := mustCompile(t, tc.source).Render(tc.data, 4000)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.Text, escapePayload) || !strings.Contains(unescape(out.Text), escapePayload) {
				t.Fatalf("payload not escaped exactly once: %q", out.Text)
			}
			assertEscaped(t, out.Text)
		})
	}
}

// TestFunctionArgumentsAreData pins the escaping contract: a string argument to a function is data
// and is escaped with the result, while markup written as literal text outside an action stays
// markup. A bold fallback is written with with/else, not with default.
func TestFunctionArgumentsAreData(t *testing.T) {
	data := Data{Vars: map[string]string{"owner": ""}}
	if got := render(t, `{{.owner | default "**none**"}}`, data); strings.Contains(got, "**none**") {
		t.Fatalf("literal argument reached the output as markup: %q", got)
	}
	if got := render(t, `{{with .owner}}{{.}}{{else}}**none**{{end}}`, data); got != "**none**" {
		t.Fatalf("literal text outside an action = %q, want **none**", got)
	}
}
