package msgmarkdown

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
)

// plain concatenates the text of a document, ignoring structure.
func plain(doc Document) string {
	var b strings.Builder
	for _, block := range doc.Blocks {
		if p, ok := block.(Paragraph); ok {
			plainInlines(&b, p.Inlines)
		}
	}
	return b.String()
}

func plainInlines(b *strings.Builder, inlines []Inline) {
	for _, n := range inlines {
		switch v := n.(type) {
		case Text:
			b.WriteString(v.Value)
		case Strong:
			plainInlines(b, v.Children)
		case Emphasis:
			plainInlines(b, v.Children)
		case Code:
			b.WriteString(v.Value)
		}
	}
}

// Every value msgtemplate interpolates must come back as exactly one Text holding the value: no
// emphasis, code, list or link can be forged from data.
func TestEscapedValuesParseAsLiteralText(t *testing.T) {
	values := []string{
		"**bold**", "*em*", "_em_", "`code`", "- not an item", "* not an item", "+ plus", "1. ordered",
		"[Reset password](https://evil.test)", "<https://evil.test>", "<!channel> <@U123> @everyone",
		"# heading", "> quote", "***", `back\slash`, `\*`, "&amp; &lt;", "a|b~c^d", "https://example.com/a_b_c",
		"x@example.com", "tab\tseparated", "ünïcödé _x_", strings.Repeat("*", 40),
	}
	for _, value := range values {
		escaped := msgtemplate.EscapeMarkdown(value)
		doc := Parse(escaped)
		if len(doc.Blocks) != 1 {
			t.Errorf("%q parsed into %d blocks", value, len(doc.Blocks))
			continue
		}
		p, ok := doc.Blocks[0].(Paragraph)
		if !ok || len(p.Inlines) != 1 {
			t.Errorf("%q parsed into %s", value, render(doc))
			continue
		}
		if text, ok := p.Inlines[0].(Text); !ok || text.Value != strings.TrimLeft(value, " ") {
			t.Errorf("%q came back as %#v", value, p.Inlines[0])
		}
	}
}

// An escaped value inside template markup keeps the markup and stays literal inside it.
func TestEscapedValueInsideTemplateMarkup(t *testing.T) {
	source := "**" + msgtemplate.EscapeMarkdown("x** evil **y") + "** and _" + msgtemplate.EscapeMarkdown("a_b") + "_"
	if got, want := render(Parse(source)), "<p><strong>x** evil **y</strong> and <em>a_b</em></p>"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func FuzzEscapedValueIsLiteral(f *testing.F) {
	for _, seed := range []string{"**a**", "`x`", "- y", "[l](u)", `\`, "*_*_", "a *b*"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		// msgtemplate sanitizes every value before escaping it: line breaks and tabs become spaces
		// and control characters are removed.
		value := msgtemplate.Sanitize(raw)
		want := strings.TrimLeft(value, " ")
		if want == "" {
			return
		}
		if got := plain(Parse(msgtemplate.EscapeMarkdown(value))); got != want {
			t.Fatalf("%q came back as %q", value, got)
		}
	})
}

func FuzzParseNeverPanics(f *testing.F) {
	for _, seed := range []string{"**a*", "`` ` ``", "- *x\n- y*", "\\\n", "***a***b**", "_é_"} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, source string) {
		_ = Parse(source)
	})
}
