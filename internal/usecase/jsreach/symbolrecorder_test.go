package jsreach

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// symbolRecorderFor wires a Tier-2 recorder over a one-module fixture.
func symbolRecorderFor(t *testing.T, graph modulegraph.Graph, result jsresolution.Result) (*SymbolRecorder, *fakeJudgments, *sbom.SBOM) {
	t.Helper()
	result.Complete = true
	result.DeclaredDependencies = append(result.DeclaredDependencies, "lodash")
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.15", PURL: lodashPURL}}}

	judgments := &fakeJudgments{}
	r, err := NewSymbolRecorder(fakeScanner{graph: graph}, fakeResolver{result: result}, judgments, fakeAudit{}, fixedClock{})
	if err != nil {
		t.Fatalf("new symbol recorder: %v", err)
	}
	return r, judgments, doc
}

// TestSymbolRecorderAttributesToTheSymbolEngine is the regression for a Tier-2 JavaScript proof being
// sealed as a Go CALL-GRAPH proof.
//
// Tier-2 is a strength of claim, not an engine: two different engines reach it. A sealed rationale that
// named the wrong one would make this module-graph proof indistinguishable from an interprocedural one
// in the report and in the audit trail, which is exactly what the reserved identities exist to prevent.
func TestSymbolRecorderAttributesToTheSymbolEngine(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{namedEdge("src/a.ts", "template")}, nil)
	r, judgments, doc := symbolRecorderFor(t, graph, result)

	minted, err := r.RecordWithSBOM(context.Background(), "eng1", "/ws", doc, []ports.ReachabilitySubject{
		{FindingID: "f1", Symbols: []string{mustSubject(t, lodashPURL, "template")}},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if minted != 1 || len(judgments.minted) != 1 {
		t.Fatalf("expected exactly one judgment, got minted=%d recorded=%d", minted, len(judgments.minted))
	}
	got := judgments.minted[0]
	if got.proposer != "system:jssymbol-scan" {
		t.Fatalf("proposer = %q, want the javascript affected-export engine, not the call-graph one", got.proposer)
	}
	if got.verifier != "system:jssymbol-engine" {
		t.Fatalf("verifier = %q, want the javascript affected-export engine", got.verifier)
	}
	if got.proposer == got.verifier {
		t.Fatal("proposer and verifier must be distinct so a proof never self-confirms")
	}
	if got.claim.Tier != judgment.Tier2 {
		t.Fatalf("tier = %q, want tier-2: an affected-export answer is stronger than an import answer", got.claim.Tier)
	}
	if got.claim.Reachable != judgment.Reachable {
		t.Fatalf("claim = %+v, want reachable", got.claim)
	}
}

// A subject the analyzer cannot answer must be DROPPED before minting, not sealed as not-reachable.
func TestSymbolRecorderDropsUnanswerableSubjects(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts",
		[]modulegraph.Edge{namespaceEdge("src/a.ts", "_")},
		[]modulegraph.LocalUse{
			{Module: "src/a.ts", Local: "_", Kind: modulegraph.LocalUseOpaque, Detail: "the binding escapes as a value"},
		})
	r, judgments, doc := symbolRecorderFor(t, graph, result)

	minted, err := r.RecordWithSBOM(context.Background(), "eng1", "/ws", doc, []ports.ReachabilitySubject{
		{FindingID: "f1", Symbols: []string{mustSubject(t, lodashPURL, "template")}},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if minted != 0 || len(judgments.minted) != 0 {
		t.Fatalf("an unanswerable subject must mint nothing, got %d", minted)
	}
}

// No coverage anywhere in the graph means nothing is minted at all: the prior tier stands.
func TestSymbolRecorderMintsNothingWhenCoverageIsIncomplete(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{namedEdge("src/a.ts", "template")}, nil)
	graph.Coverage = []modulegraph.CoverageIssue{{Kind: modulegraph.CoverageEval, Path: "src/a.ts"}}
	r, judgments, doc := symbolRecorderFor(t, graph, result)

	if _, err := r.RecordWithSBOM(context.Background(), "eng1", "/ws", doc, []ports.ReachabilitySubject{
		{FindingID: "f1", Symbols: []string{mustSubject(t, lodashPURL, "template")}},
	}); err == nil {
		t.Fatal("a coverage issue must abort the pass rather than mint a judgment")
	}
	if len(judgments.minted) != 0 {
		t.Fatalf("nothing may be minted from an incomplete scan, got %d", len(judgments.minted))
	}
}

func TestSymbolRecorderValidatesDependencies(t *testing.T) {
	t.Parallel()

	if _, err := NewSymbolRecorder(nil, fakeResolver{}, &fakeJudgments{}, fakeAudit{}, fixedClock{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil scanner must be rejected, got %v", err)
	}
	graph, result := graphWith("src/a.ts", nil, nil)
	r, _, _ := symbolRecorderFor(t, graph, result)
	if _, err := r.RecordWithSBOM(context.Background(), "eng1", "/ws", nil, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("recording without the sbom the subjects were minted from must be refused, got %v", err)
	}
}
