package msgmarkdown

import "testing"

func TestParseBlocks(t *testing.T) {
	cases := map[string]string{
		"":                                 "",
		"one":                              "<p>one</p>",
		"one\ntwo":                         "<p>one<br>two</p>",
		"one\r\ntwo\rthree":                "<p>one<br>two<br>three</p>",
		"one\n\ntwo":                       "<p>one</p><p>two</p>",
		"intro\n- a\n- b\nafter":           "<p>intro</p><ul><li>a</li><li>b</li></ul><p>after</p>",
		"* a\n+ b\n   - c":                 "<ul><li>a</li><li>b</li><li>c</li></ul>",
		"- a\n\n- b":                       "<ul><li>a</li></ul><ul><li>b</li></ul>",
		"-\n- b":                           "<ul><li></li><li>b</li></ul>",
		"    - four spaces":                "<p>- four spaces</p>",
		"-1 is not an item":                "<p>-1 is not an item</p>",
		"**bold** line":                    "<p><strong>bold</strong> line</p>",
		"- **bold** item":                  "<ul><li><strong>bold</strong> item</li></ul>",
		"***":                              "<p>***</p>",
		"- - -":                            "<p>- - -</p>",
		"# not a heading":                  "<p># not a heading</p>",
		"> not a quote":                    "<p>> not a quote</p>",
		"```\nnot a fence\n```":            "<p><code>not a fence</code></p>", // no fences: an inline code span
		`\- escaped marker`:                "<p>- escaped marker</p>",
		"  indented paragraph":             "<p>indented paragraph</p>",
		"*a\nb*":                           "<p><em>a<br>b</em></p>",
		"- *open\n- close*":                "<ul><li>*open</li><li>close*</li></ul>",
		"title\n\n\n":                      "<p>title</p>",
		"- item\ncontinued is a paragraph": "<ul><li>item</li></ul><p>continued is a paragraph</p>",
	}
	for source, want := range cases {
		if got := render(Parse(source)); got != want {
			t.Errorf("%q\n got  %s\n want %s", source, got, want)
		}
	}
}
