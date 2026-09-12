package symbolcanon

import "testing"

func TestCanonicalizePerLanguageForms(t *testing.T) {
	cases := []struct {
		name string
		lang Language
		raw  string
		want []string
	}{
		{"rust qualified", Rust, "smallvec::SmallVec::grow", []string{"smallvec", "SmallVec", "grow"}},
		{"rust hyphen crate + leading ::", Rust, "::foo-bar::Baz::run", []string{"foo_bar", "Baz", "run"}},
		{"rust generics dropped", Rust, "serde_json::Value::<T>::get", []string{"serde_json", "Value", "get"}},
		{"go path.recv.method", Go, "github.com/x/y/pkg.Recv.Method", []string{"github", "com", "x", "y", "pkg", "Recv", "Method"}},
		{"go pointer receiver + generics", Go, "pkg.(*Server[T]).Handle", []string{"pkg", "Server", "Handle"}},
		{"php namespaced method", PHP, `Monolog\Logger::addRecord`, []string{"Monolog", "Logger", "addRecord"}},
		{"ruby module class method", Ruby, "Nokogiri::XML::Document#parse", []string{"Nokogiri", "XML", "Document", "parse"}},
		{"dotnet type member + arity", DotNet, "System.Text.Json.JsonSerializer`1.Deserialize", []string{"System", "Text", "Json", "JsonSerializer", "Deserialize"}},
		{"generic superset", Generic, "a::b.c/d", []string{"a", "b", "c", "d"}},
		{"empty", Rust, "   ::  ", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Canonicalize(c.lang, c.raw).Segments
			if len(got) != len(c.want) {
				t.Fatalf("segments = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("segments = %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestTailMatch(t *testing.T) {
	adv := Canonicalize(Rust, "smallvec::SmallVec::grow")
	// Observed reference in first-party source, qualified by owner.
	hit := Canonicalize(Rust, "smallvec::SmallVec::grow")
	if !TailMatch(adv, hit, 2) {
		t.Fatal("qualified same symbol must tail-match at n=2")
	}
	// A same-named leaf with a different owner must NOT match at n=2 (raise-only soundness: never
	// raise on a bare local grow()).
	other := Canonicalize(Rust, "mymod::LocalThing::grow")
	if TailMatch(adv, other, 2) {
		t.Fatal("different owner must not tail-match at n=2")
	}
	// A bare leaf (one segment) never matches at n=2.
	bare := Canonicalize(Rust, "grow")
	if TailMatch(adv, bare, 2) {
		t.Fatal("bare leaf must not tail-match at n=2")
	}
	if TailMatch(adv, hit, 0) {
		t.Fatal("n=0 never matches")
	}
}

// TestSymmetry is the core property: a symbol canonicalized on the advisory side and the same symbol
// (possibly spelled with hyphen/underscore, generics, or a pointer receiver) canonicalized on the
// observed side must be Equal. A mismatch here is a silent false negative.
func TestSymmetry(t *testing.T) {
	pairs := []struct {
		lang     Language
		advisory string
		observed string
	}{
		{Rust, "foo-bar::Baz::run", "foo_bar::Baz::run"},
		{Rust, "serde::de::Deserialize::<T>::deserialize", "serde::de::Deserialize::deserialize"},
		{Go, "pkg.(*Server).Handle", "pkg.Server.Handle"},
		{DotNet, "N.T`1.M", "N.T.M"},
	}
	for _, p := range pairs {
		if !Equal(Canonicalize(p.lang, p.advisory), Canonicalize(p.lang, p.observed)) {
			t.Errorf("%s: advisory %q and observed %q must canonicalize equal", p.lang, p.advisory, p.observed)
		}
	}
}

func TestLooksMangled(t *testing.T) {
	for _, m := range []string{"_ZN4core3fmt3Foo", "_RNvC1a", "?func@@YAXXZ"} {
		if !LooksMangled(m) {
			t.Errorf("%q must be flagged mangled (demangle at extraction, do not canonicalize)", m)
		}
	}
	for _, plain := range []string{"smallvec::SmallVec::grow", "pkg.Recv.Method", ""} {
		if LooksMangled(plain) {
			t.Errorf("%q must not be flagged mangled", plain)
		}
	}
}

func TestRubyOperatorAndMethodKind(t *testing.T) {
	// Operator methods must survive (no generic-stripping for Ruby).
	for raw, want := range map[string][]string{
		"Array#[]":       {"Array", "[]"},
		"Array#[]=":      {"Array", "[]="},
		"Comparable#<=>": {"Comparable", "<=>"},
		"Numeric#*":      {"Numeric", "*"},
		"Numeric#**":     {"Numeric", "**"},
		"Set#&":          {"Set", "&"},
	} {
		got := Canonicalize(Ruby, raw).Segments
		if len(got) != len(want) || (len(got) == 2 && (got[0] != want[0] || got[1] != want[1])) {
			t.Errorf("Canonicalize(Ruby, %q) = %v, want %v", raw, got, want)
		}
	}
	// A class method (Foo.bar) must NOT canonicalize equal to the instance method (Foo#bar): distinct
	// Ruby call targets, so conflating them would false-positive raise.
	if Equal(Canonicalize(Ruby, "Foo.bar"), Canonicalize(Ruby, "Foo#bar")) {
		t.Error("Ruby class method Foo.bar must not equal instance method Foo#bar")
	}
}

func TestGenericIsLossless(t *testing.T) {
	// Generic applies no hyphen normalization and no generic-strip, so a hyphen is preserved and a
	// bracketed method name survives.
	got := Canonicalize(Generic, "foo-bar/pkg.Func").Segments
	want := []string{"foo-bar", "pkg", "Func"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("Generic lossless: got %v want %v", got, want)
	}
}

func TestLooksMangledMachO(t *testing.T) {
	for _, m := range []string{"__ZN4core3fmt", "__RNvC1a"} {
		if !LooksMangled(m) {
			t.Errorf("Mach-O platform-prefixed %q must be flagged mangled", m)
		}
	}
}
