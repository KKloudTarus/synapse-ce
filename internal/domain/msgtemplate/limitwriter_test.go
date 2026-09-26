package msgtemplate

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRenderTruncatesWithMarker(t *testing.T) {
	tmpl := mustCompile(t, "Title: {{.title}}")
	out, err := tmpl.Render(Data{Vars: map[string]string{"title": strings.Repeat("x", 100)}}, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated || out.Text != "Title: xxxxxxxxxxxx…" || utf8.RuneCountInString(out.Text) != 20 {
		t.Fatalf("got %+v (%d runes)", out, utf8.RuneCountInString(out.Text))
	}
	out, err = tmpl.Render(Data{Vars: map[string]string{"title": "ok"}}, 20)
	if err != nil || out.Truncated || out.Text != "Title: ok" {
		t.Fatalf("got %+v, %v", out, err)
	}
	exact, err := tmpl.Render(Data{Vars: map[string]string{"title": strings.Repeat("y", 13)}}, 20)
	if err != nil || exact.Truncated || utf8.RuneCountInString(exact.Text) != 20 {
		t.Fatalf("exact fit got %+v, %v", exact, err)
	}
}

func TestRenderTruncationKeepsWholeRunes(t *testing.T) {
	vi := strings.Repeat(string(rune(0x1ec7)), 50)
	out, err := mustCompile(t, "{{.title}}").Render(Data{Vars: map[string]string{"title": vi}}, 10)
	if err != nil || !utf8.ValidString(out.Text) || utf8.RuneCountInString(out.Text) != 10 {
		t.Fatalf("got %q, %v", out.Text, err)
	}
}

func TestLimitWriterStopsAtBudget(t *testing.T) {
	w := &limitWriter{max: 5}
	if n, err := w.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("first write = %d, %v", n, err)
	}
	if n, err := w.Write([]byte("defg")); n != 2 || !errors.Is(err, errOutputLimit) {
		t.Fatalf("overflowing write = %d, %v", n, err)
	}
	if out := w.output(); !out.Truncated || out.Text != "abcd…" {
		t.Fatalf("output = %+v", out)
	}
}

func TestTruncateRunes(t *testing.T) {
	cases := []struct {
		value string
		max   int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 4, "hel…"},
		{"hello", 1, "…"},
		{"hello", 0, ""},
		{"hello", -1, ""},
	}
	for _, tc := range cases {
		if got := truncateRunes(tc.value, tc.max); got != tc.want {
			t.Fatalf("truncateRunes(%q, %d) = %q, want %q", tc.value, tc.max, got, tc.want)
		}
	}
}
