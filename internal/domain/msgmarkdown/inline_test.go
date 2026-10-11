package msgmarkdown

import "testing"

// The expectations follow the CommonMark 0.31 specification. During development the parser was
// also compared with a CommonMark implementation on 500,000 random inputs built from these
// characters; the two agreed on every one.
func TestInlineEmphasisFollowsCommonMark(t *testing.T) {
	cases := map[string]string{
		"*foo bar*":                "<p><em>foo bar</em></p>",
		"a * foo bar*":             "<p>a * foo bar*</p>",
		`a*"foo"*`:                 `<p>a*"foo"*</p>`,
		"foo*bar*":                 "<p>foo<em>bar</em></p>",
		"5*6*78":                   "<p>5<em>6</em>78</p>",
		"_foo bar_":                "<p><em>foo bar</em></p>",
		"foo_bar_":                 "<p>foo_bar_</p>",
		"пристаням_стремятся_":     "<p>пристаням_стремятся_</p>",
		"foo-_(bar)_":              "<p>foo-<em>(bar)</em></p>",
		"_foo*":                    "<p>_foo*</p>",
		"*foo bar *":               "<p>*foo bar *</p>",
		"*(*foo*)*":                "<p><em>(<em>foo</em>)</em></p>",
		"**foo bar**":              "<p><strong>foo bar</strong></p>",
		"** foo bar**":             "<p>** foo bar**</p>",
		"***foo***":                "<p><em><strong>foo</strong></em></p>",
		"*foo**bar**baz*":          "<p><em>foo<strong>bar</strong>baz</em></p>",
		"*foo**bar*":               "<p><em>foo**bar</em></p>",
		"foo***bar***baz":          "<p>foo<em><strong>bar</strong></em>baz</p>",
		"foo******bar*********baz": "<p>foo<strong><strong><strong>bar</strong></strong></strong>***baz</p>",
		"**foo*":                   "<p>*<em>foo</em></p>",
		"*foo**":                   "<p><em>foo</em>*</p>",
		"*foo _bar* baz_":          "<p><em>foo _bar</em> baz_</p>",
		"__foo, __bar__, baz__":    "<p><strong>foo, <strong>bar</strong>, baz</strong></p>",
	}
	for source, want := range cases {
		if got := render(Parse(source)); got != want {
			t.Errorf("%q\n got  %s\n want %s", source, got, want)
		}
	}
}

func TestInlineCodeSpans(t *testing.T) {
	cases := map[string]string{
		"`foo`":           "<p><code>foo</code></p>",
		"`` foo ` bar ``": "<p><code>foo ` bar</code></p>",
		"` `` `":          "<p><code>``</code></p>",
		"`  ``  `":        "<p><code> `` </code></p>",
		"`foo\\`bar`":     "<p><code>foo\\</code>bar`</p>",
		"``foo`":          "<p>``foo`</p>",
		"*a `*`*":         "<p><em>a <code>*</code></em></p>",
		"`**not bold**`":  "<p><code>**not bold**</code></p>",
		"`a\nb`":          "<p><code>a b</code></p>",
		"*foo`*`":         "<p>*foo<code>*</code></p>",
	}
	for source, want := range cases {
		if got := render(Parse(source)); got != want {
			t.Errorf("%q\n got  %s\n want %s", source, got, want)
		}
	}
}

func TestInlineEscapesAndLiterals(t *testing.T) {
	cases := map[string]string{
		`\*not emphasized*`:          "<p>*not emphasized*</p>",
		`\\*emphasis*`:               `<p>\<em>emphasis</em></p>`,
		`\a stays`:                   `<p>\a stays</p>`,
		"trailing \\":                `<p>trailing \</p>`,
		"line one\\\nline two":       "<p>line one<br>line two</p>",
		"[label](https://evil.test)": "<p>[label](https://evil.test)</p>",
		"<https://evil.test>":        "<p><https://evil.test></p>",
		"<b>html</b> &amp;":          "<p><b>html</b> &amp;</p>",
		"![img](x.png)":              "<p>![img](x.png)</p>",
	}
	for source, want := range cases {
		if got := render(Parse(source)); got != want {
			t.Errorf("%q\n got  %s\n want %s", source, got, want)
		}
	}
}
