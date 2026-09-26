package msgtemplate

import (
	"testing"
	"unicode/utf8"
)

func TestRenderSanitizesControlCharacters(t *testing.T) {
	value := "a\nb\r\tc" + string(rune(0x202e)) + "d" + string(rune(0x200b)) + "e" + string(rune(0x0007)) + "f" + string(rune(0x0085)) + "g" + string(rune(0xfeff)) + "h\xff"
	got := render(t, "{{.title}}", Data{Vars: map[string]string{"title": value}})
	if want := "a b  cdefgh" + string(utf8.RuneError); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSanitizeRemovesInvisibleCharacters(t *testing.T) {
	value := "a" + string(rune(0x00ad)) + "b" + string(rune(0xe0041)) + "c" + string(rune(0x2062)) + "d" + string(rune(0xfffa)) + "e"
	if got := Sanitize(value); got != "abcde" {
		t.Fatalf("got %q", got)
	}
}
