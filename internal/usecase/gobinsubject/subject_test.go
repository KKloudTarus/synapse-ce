package gobinsubject

import "testing"

func TestEncodeAndParseBindSymbolToExactGoPURL(t *testing.T) {
	const purl = "pkg:golang/example.com/module@v1.2.3"
	encoded, ok := Encode(purl, "example.com/module/pkg.Vulnerable")
	if !ok || encoded != purl+"#example.com/module/pkg.Vulnerable" {
		t.Fatalf("Encode = %q, %v", encoded, ok)
	}
	parsed, symbol, ok := Parse(encoded)
	if !ok || parsed != (PURL{Raw: purl, Module: "example.com/module", Version: "v1.2.3"}) || symbol != "example.com/module/pkg.Vulnerable" {
		t.Fatalf("Parse = %+v, %q, %v", parsed, symbol, ok)
	}
	root, ok := Encode(purl, "example.com/module.Root")
	if !ok || root != purl+"#example.com/module.Root" {
		t.Fatalf("root Encode = %q, %v", root, ok)
	}
	if _, symbol, ok := Parse(root); !ok || symbol != "example.com/module.Root" {
		t.Fatalf("root Parse = %q, %v", symbol, ok)
	}
	unicodeRoot, ok := Encode(purl, "example.com/module.Évaluer")
	if !ok || unicodeRoot != purl+"#example.com/module.Évaluer" {
		t.Fatalf("Unicode root Encode = %q, %v", unicodeRoot, ok)
	}
}

func TestCodecRejectsAmbiguousOrUnownedQueries(t *testing.T) {
	for _, input := range []string{
		"pkg:golang/example.com/module@v1.2.3?x=y#example.com/module/pkg.Vulnerable",
		"pkg:golang/example.com/module@v1.2.3#other.example/pkg.Vulnerable",
		"pkg:golang/example.com/module@v1.2.3#example.com/module.Root.Method",
		"pkg:golang/example.com/module@v1.2.3#example.com/module.v2/pkg.Vulnerable",
		"pkg:golang/example.com/module@v1.2.3#example.com/module/pkg.Vulnerable[int]",
		"pkg:golang/example.com/module@v1.2.3#example.com/module/pkg.Vulnerable[github.com/other.Type]",
		"pkg:golang/stdlib@1.24.11#net/http.ListenAndServe",
		"pkg:golang/example.com/module@v1.2.3#example.com/module/pkg.Vulnerable#extra",
		"pkg:golang/example.com/module@v1.2.3#",
	} {
		if _, _, ok := Parse(input); ok {
			t.Fatalf("Parse accepted %q", input)
		}
	}
	if _, ok := Encode("pkg:golang/example.com/module@v1.2.3", "other.example/pkg.Vulnerable"); ok {
		t.Fatal("Encode accepted an unowned symbol")
	}
	for _, symbol := range []string{"example.com/module.Root.Method", "example.com/module.v2/pkg.Vulnerable", "example.com/module/pkg.Vulnerable[int]"} {
		if _, ok := Encode("pkg:golang/example.com/module@v1.2.3", symbol); ok {
			t.Fatalf("Encode accepted ambiguous symbol %q", symbol)
		}
	}
}
