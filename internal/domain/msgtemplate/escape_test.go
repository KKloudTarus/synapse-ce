package msgtemplate

import (
	"testing"
)

func TestRenderEscapesInterpolatedValues(t *testing.T) {
	title := "[Reset password](https://evil.example) **bold** <!channel> @everyone _i_ `code` ~s~ a|b"
	got := render(t, `**{{.title}}**`, Data{Vars: map[string]string{"title": title}})
	want := "**" + `\[Reset password\](https://evil.example) \*\*bold\*\* \<!channel\> @everyone \_i\_ ` + "\\`code\\`" + ` \~s\~ a\|b` + "**"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestRenderEscapesBlockMarkupAtValueStart(t *testing.T) {
	cases := map[string]string{
		"- item":     `\- item`,
		"  + item":   `  \+ item`,
		"# heading":  `\# heading`,
		"12. item":   `12\. item`,
		"3) item":    `3\) item`,
		"2024 - ok":  `2024 - ok`,
		"CVE-2024-1": `CVE-2024-1`,
	}
	for value, want := range cases {
		if got := render(t, "{{.title}}", Data{Vars: map[string]string{"title": value}}); got != want {
			t.Fatalf("value %q rendered %q, want %q", value, got, want)
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

func TestEscapeMarkdown(t *testing.T) {
	cases := map[string]string{
		"plain text":   "plain text",
		`a\b`:          `a\\b`,
		"*x* _y_":      `\*x\* \_y\_`,
		"[t](u)":       `\[t\](u)`,
		"<!here>":      `\<!here\>`,
		"a|b~c`d":      `a\|b\~c\` + "`d",
		"- item":       `\- item`,
		"# title":      `\# title`,
		"1. first":     `1\. first`,
		"2024-09 - ok": "2024-09 - ok",
		"":             "",
	}
	for in, want := range cases {
		if got := EscapeMarkdown(in); got != want {
			t.Fatalf("EscapeMarkdown(%q) = %q, want %q", in, got, want)
		}
	}
}
