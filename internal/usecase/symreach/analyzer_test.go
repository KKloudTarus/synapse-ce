package symreach

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
)

type fakeScanner struct {
	refs []string
	err  error
}

func (f fakeScanner) ScanSymbolRefs(context.Context, string) ([]string, error) { return f.refs, f.err }

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
