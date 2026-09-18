//go:build cgo

package reachbench

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/astwalk"
)

type captureInterprocFacts struct{}

func (captureInterprocFacts) JsFacts(ctx context.Context, root string) (jsprogram.Document, bool, error) {
	document, err := astwalk.JsFactsFor(ctx, root)
	return document, err == nil, err
}

func (captureInterprocFacts) PythonFacts(context.Context, string) (pythonprogram.Document, bool, error) {
	return pythonprogram.Document{}, false, nil
}

func TestJavaScriptInterproceduralCaptureUsesFirstPartySymbolQueries(t *testing.T) {
	specification := materializerFixture(t, "javascript-interprocedural-input")
	fixture, err := newFixtureMaterializer(t, &fixtureToolRunner{}, "linux/amd64").Materialize(context.Background(), FixtureMaterializationRequest{
		Specification: specification,
		WorkRoot:      privateMaterializerRoot(t),
		CellKey:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if err != nil {
		t.Fatal(err)
	}
	capture := &ProductionCapture{facts: captureInterprocFacts{}}
	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"pkg:reachbench/javascript/interprocedural#functionAliasTarget",
		"pkg:reachbench/javascript/interprocedural#callbackTarget",
		"pkg:reachbench/javascript/interprocedural#returnedCallableTarget",
		"pkg:reachbench/javascript/interprocedural#crossModuleTarget",
	} {
		resolved := fixtureSubjectByID(t, specification, id)
		if _, err := runJavaScriptInterprocedural(context.Background(), capture, fixture, resolved, lifecycle); err != nil {
			t.Fatalf("capture %q: %v", id, err)
		}
	}
	judgments, err := lifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
	if err != nil {
		t.Fatal(err)
	}
	claims := judgment.WinningReachabilityClaims(judgments)
	if len(claims) != 4 {
		t.Fatalf("first-party interprocedural claims = %#v, want four reached symbols", claims)
	}
	for _, claim := range claims {
		if claim.Reachable != judgment.Reachable || claim.SuppressesFinding() {
			t.Fatalf("local interprocedural claim = %#v, want non-suppressing reachable", claim)
		}
	}
}
