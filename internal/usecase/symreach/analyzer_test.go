package symreach

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

type fakeScanner struct {
	refs []string
	err  error
}

func (f fakeScanner) ScanSymbolRefs(context.Context, string) ([]string, error) { return f.refs, f.err }

type fakeProvenanceScanner struct {
	fakeScanner
	local []SymbolReference
}

func (f fakeProvenanceScanner) ScanSymbolRefsWithProvenance(context.Context, string) ([]string, []SymbolReference, error) {
	return f.refs, f.local, f.err
}

func TestSymreachRaiseOnlyMatch(t *testing.T) {
	a, err := New("composer", symbolcanon.PHP, fakeScanner{refs: []string{`Monolog\Handler\StreamHandler::write`}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Analyzeable() != "composer" {
		t.Fatalf("Analyzeable = %q", a.Analyzeable())
	}
	res, err := a.Analyze(context.Background(), "/work", []string{
		`Monolog\Handler\StreamHandler::write`, // referenced -> reachable
		`Other\Vendor\Class::unused`,           // not referenced -> absent (raise-only omits it)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 {
		t.Fatalf("only the referenced symbol may produce a result, got %+v", res.Results)
	}
	if r := res.Results[0]; r.Symbol != `Monolog\Handler\StreamHandler::write` || !r.Reachable {
		t.Fatalf("referenced curated symbol must be reachable, got %+v", r)
	}
	// The analyzer is physically incapable of a not-reachable verdict: every result is Reachable=true.
	for _, r := range res.Results {
		if !r.Reachable {
			t.Fatalf("symreach must never emit a not-reachable result, got %+v", r)
		}
	}
}

func TestSymreachBareSymbolNeverMatches(t *testing.T) {
	// A bare one-segment reference/subject is not a sound identity and must never match (a same-named local).
	a, _ := New("gem", symbolcanon.Ruby, fakeScanner{refs: []string{"write"}})
	res, err := a.Analyze(context.Background(), "/work", []string{"write", "Foo::Bar#write"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 0 {
		t.Fatalf("a bare reference must not match a qualified subject, got %+v", res.Results)
	}
}

func TestSymreachTailMatchAcrossVendorPrefix(t *testing.T) {
	// The advisory subject and the observed reference share the owner+member tail but differ in prefix depth;
	// symbolcanon tail-match (2 segments) ties the function to its immediate owner regardless of prefix.
	a, _ := New("nuget", symbolcanon.DotNet, fakeScanner{refs: []string{"Newtonsoft.Json.JsonConvert.DeserializeObject"}})
	res, err := a.Analyze(context.Background(), "/work", []string{"Json.JsonConvert.DeserializeObject"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 || !res.Results[0].Reachable {
		t.Fatalf("tail-match on owner+member must raise, got %+v", res.Results)
	}
}

// TestSymreachCppRaiseOnly: a C/C++ (conan) qualified reference tail-matches the curated vulnerable symbol
// and raises it; a bare/one-segment subject never matches; the analyzer is incapable of not-reachable.
func TestSymreachCppRaiseOnly(t *testing.T) {
	a, err := New("conan", symbolcanon.Cpp, fakeScanner{refs: []string{"curl::easy::perform", "app::mod::use"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Analyzeable() != "conan" {
		t.Fatalf("Analyzeable = %q", a.Analyzeable())
	}
	res, err := a.Analyze(context.Background(), "/work", []string{
		"curl::easy::perform", // referenced -> reachable
		"other::pkg::unused",  // not referenced -> absent (raise-only omits it)
		"perform",             // bare leaf -> never matches
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 || res.Results[0].Symbol != "curl::easy::perform" || !res.Results[0].Reachable {
		t.Fatalf("only the referenced curated symbol may raise, got %+v", res.Results)
	}
	for _, r := range res.Results {
		if !r.Reachable {
			t.Fatalf("symreach must never emit a not-reachable result, got %+v", r)
		}
	}
}

// A C++ template instantiation in the observed reference tail-matches a template-free advisory subject
// (symbolcanon strips the <...> on both sides).
func TestSymreachCppTemplateTailMatch(t *testing.T) {
	a, _ := New("conan", symbolcanon.Cpp, fakeScanner{refs: []string{"boost::regex::match<char>"}})
	res, err := a.Analyze(context.Background(), "/work", []string{"boost::regex::match"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 || !res.Results[0].Reachable {
		t.Fatalf("a templated reference must match the template-free subject, got %+v", res.Results)
	}
}

func TestSymreachLocalPHPAndRubyReferencesCarryDeclarationProvenance(t *testing.T) {
	tests := []struct {
		name       string
		purlType   string
		language   symbolcanon.Language
		symbol     string
		provenance SymbolReference
	}{
		{
			name: "php", purlType: "composer", language: symbolcanon.PHP, symbol: "symbolPositive",
			provenance: SymbolReference{Symbol: "symbolPositive", ModulePath: "fixtures/php/symbols_tier2/main.php", Line: 25},
		},
		{
			name: "ruby", purlType: "gem", language: symbolcanon.Ruby, symbol: "symbol_positive",
			provenance: SymbolReference{Symbol: "symbol_positive", ModulePath: "fixtures/ruby/symbols_tier2/main.rb", Line: 18},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := New(tt.purlType, tt.language, fakeProvenanceScanner{local: []SymbolReference{tt.provenance}})
			if err != nil {
				t.Fatal(err)
			}
			analysis, err := a.Analyze(context.Background(), "/work", []string{tt.symbol, "unresolved"})
			if err != nil {
				t.Fatal(err)
			}
			if len(analysis.Results) != 1 || !analysis.Results[0].Reachable || analysis.Results[0].Symbol != tt.symbol {
				t.Fatalf("local result = %#v", analysis.Results)
			}
			want := &reachability.SourceProvenance{ModulePath: tt.provenance.ModulePath, Line: tt.provenance.Line}
			if got := analysis.Results[0].Provenance; got == nil || *got != *want {
				t.Fatalf("local provenance = %#v, want %#v", got, want)
			}
			for _, result := range analysis.Results {
				if !result.Reachable {
					t.Fatalf("symreach must remain raise-only, got %#v", result)
				}
			}
		})
	}
}

func TestSymreachDropsUnsafeLocalProvenance(t *testing.T) {
	a, err := New("composer", symbolcanon.PHP, fakeProvenanceScanner{local: []SymbolReference{
		{Symbol: "target", ModulePath: "/private/materialization/main.php", Line: 9},
		{Symbol: "target", ModulePath: "../outside.php", Line: 9},
		{Symbol: "target", ModulePath: `C:\\private\\main.php`, Line: 9},
	}})
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := a.Analyze(context.Background(), "/work", []string{"target"})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 0 {
		t.Fatalf("unsafe provenance must not mint a positive result: %#v", analysis.Results)
	}
}
