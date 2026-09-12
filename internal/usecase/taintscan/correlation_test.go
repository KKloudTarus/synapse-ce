package taintscan

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCorrelateSASTFindingsMatchesOnlyWholeCanonicalSymbols(t *testing.T) {
	subjects := []ports.ReachabilitySubject{
		{FindingID: "z-unrelated", Symbols: []string{"example.com/other.Parser.Parse"}},
		{FindingID: "b-match", Symbols: []string{"example.com/lib.(*Parser).Parse[string]"}},
		{FindingID: "a-match", Symbols: []string{"example.com/lib.Parser.Parse"}},
		{FindingID: "bare-leaf", Symbols: []string{"Parse"}},
	}
	links := correlateSASTFindings(symbolcanon.Go, []string{"example.com/lib.Parser.Parse"}, subjects)
	if len(links) != 2 {
		t.Fatalf("want two exact advisory matches, got %+v", links)
	}
	if links[0].FindingID != "a-match" || links[1].FindingID != "b-match" {
		t.Fatalf("links must be sorted by finding id, got %+v", links)
	}
	if links[0].SinkSymbol != "example.com/lib.Parser.Parse" || links[0].AffectedSymbol != "example.com/lib.Parser.Parse" {
		t.Fatalf("link must preserve the exact matched symbols, got %+v", links[0])
	}
	if got := (judgment.SASTClaim{Correlations: links}).CorrelatedFindingIDs(); len(got) != 2 || got[0] != shared.ID("a-match") || got[1] != shared.ID("b-match") {
		t.Fatalf("correlated ids = %v, want [a-match b-match]", got)
	}
}

func TestCorrelateSASTFindingsNeverFabricatesLinkForSameNamedLocal(t *testing.T) {
	links := correlateSASTFindings(symbolcanon.Go, []string{"app.Parse"}, []ports.ReachabilitySubject{{
		FindingID: "finding-1", Symbols: []string{"example.com/lib.Parser.Parse", "Parse"},
	}})
	if len(links) != 0 {
		t.Fatalf("a same-named local or bare leaf must not link to an advisory: %+v", links)
	}
}
