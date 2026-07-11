package duplication

import "testing"

func toksText(ts []token) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.text
	}
	return out
}

func TestTokenizeStripsComments(t *testing.T) {
	// Trailing line comment and a block comment must be dropped; code tokens survive.
	src := "x = a + b // add them\n/* block\ncomment */\ny = c\n"
	ts, codeLines := tokenize("Go", []byte(src))
	got := toksText(ts)
	want := []string{"x", "=", "a", "+", "b", "y", "=", "c"}
	if len(got) != len(want) {
		t.Fatalf("tokens = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token %d = %q, want %q (all %v)", i, got[i], want[i], got)
		}
	}
	if codeLines != 2 { // line 1 (x=a+b) and line 4 (y=c); the block-comment lines have no code
		t.Errorf("codeLines = %d, want 2", codeLines)
	}
}

func TestTokenizeLineNumbers(t *testing.T) {
	ts, _ := tokenize("Go", []byte("a\n\nb\n"))
	if len(ts) != 2 || ts[0].line != 1 || ts[1].line != 3 {
		t.Errorf("line numbers wrong: %+v", ts)
	}
}

func TestTokenizeInlineBlockComment(t *testing.T) {
	// Code, an inline block comment, then more code on the same line.
	ts, _ := tokenize("Go", []byte("a /* x */ b\n"))
	got := toksText(ts)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("inline block comment not stripped: %v", got)
	}
}
