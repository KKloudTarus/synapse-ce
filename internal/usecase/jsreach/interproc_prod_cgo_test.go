//go:build cgo

package jsreach

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/astwalk"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// prodFactsProvider is the real synapse-ast extractor, so this test drives the whole production path:
// raw subject -> encode -> coordinator -> analyzer -> real Resolve -> external node -> mint.
type prodFactsProvider struct{}

func (prodFactsProvider) JsFacts(ctx context.Context, root string) (jsprogram.Document, bool, error) {
	doc, err := astwalk.JsFactsFor(ctx, root)
	if err != nil {
		return jsprogram.Document{}, false, err
	}
	return doc, true, nil
}

// prodJudgments is a minimal in-memory judgment lifecycle: Propose records a proposed judgment, Verify
// confirms it, List returns the confirmed ones (so the coordinator's prior-supersession sees them).
type prodJudgments struct {
	items []judgment.Judgment
	n     int
}

func (p *prodJudgments) Propose(_ context.Context, _ string, _ shared.ID, capability judgment.Capability, kind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	p.n++
	j := judgment.Judgment{
		ID: shared.ID("j" + strconv.Itoa(p.n)), Version: 1, State: judgment.StateProposed,
		Capability: capability, SubjectKind: kind, SubjectID: subjectID, Claim: claim,
	}
	p.items = append(p.items, j)
	return j, nil
}

func (p *prodJudgments) Verify(_ context.Context, _ string, _, judgmentID shared.ID, _ int, _ string, _ int) (judgment.Judgment, error) {
	for i := range p.items {
		if p.items[i].ID == judgmentID {
			p.items[i].State = judgment.StateConfirmed
			return p.items[i], nil
		}
	}
	return judgment.Judgment{}, nil
}

func (p *prodJudgments) List(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return p.items, nil
}

type prodAudit struct{}

func (prodAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type prodClock struct{}

func (prodClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func writeApp(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFirstPartyInterprocFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	main := `import { crossModuleTarget } from "./module.mjs";

function entry() {
  const alias = functionAliasTarget;
  alias();
  invokeSynchronously(callbackTarget);
  returnedCallable()();
  crossModuleTarget();
}

function functionAliasTarget() {}
function callbackTarget() {}
function invokeSynchronously(callback) { callback(); }
function returnedCallable() { return returnedCallableTarget; }
function returnedCallableTarget() {}

entry();
`
	if err := os.WriteFile(filepath.Join(dir, "main.mjs"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module.mjs"), []byte("export function crossModuleTarget() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestInterprocAnalyzerReachesFirstPartySymbolsFromRealFacts(t *testing.T) {
	dir := writeFirstPartyInterprocFixture(t)
	analyzer, err := NewInterprocAnalyzer(prodFactsProvider{})
	if err != nil {
		t.Fatal(err)
	}
	queries := make([]string, 0, 4)
	for _, item := range []struct{ module, symbol string }{
		{"main.mjs", "functionAliasTarget"},
		{"main.mjs", "callbackTarget"},
		{"main.mjs", "returnedCallableTarget"},
		{"module.mjs", "crossModuleTarget"},
	} {
		subject, ok := FirstPartySymbolSubject(item.module, item.symbol)
		if !ok {
			t.Fatalf("build first-party subject for %#v", item)
		}
		queries = append(queries, subject)
	}
	analysis, err := analyzer.Analyze(context.Background(), dir, queries)
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != len(queries) {
		t.Fatalf("first-party results = %#v, want all %v", analysis.Results, queries)
	}
	for index, result := range analysis.Results {
		if result.Symbol != queries[index] || !result.Reachable || len(result.Path) < 2 {
			t.Fatalf("result %d = %#v, want a reached local call path", index, result)
		}
	}
}

// TestInterprocRecorderMintsFromRawSubjectsEndToEnd is the production-path test the unit tests could not
// give: it feeds the recorder the RAW (PackagePURL + affected symbol) subject the SCA pass actually
// produces (not a pre-encoded one), over a real extracted call graph, and asserts a raise-only reachable
// Tier-2 judgment is minted when a first-party wrapper reaches into the package, and nothing when it does
// not. This guards the "wired behind the wrong input" regression: the recorder must encode raw subjects
// itself.
func TestInterprocRecorderMintsFromRawSubjectsEndToEnd(t *testing.T) {
	rawSubjects := []ports.ReachabilitySubject{
		{FindingID: "f-lodash", PackagePURL: "pkg:npm/lodash@4.17.20", Symbols: []string{"template"}},
	}

	// Reached: a first-party wrapper called from module top level calls lodash.template.
	reachedDir := writeApp(t, "import { template } from 'lodash';\nfunction render(x) { return template(x); }\nrender('hi');\n")
	rec, err := NewInterprocRecorder(prodFactsProvider{}, &prodJudgments{}, prodAudit{}, prodClock{})
	if err != nil {
		t.Fatal(err)
	}
	minted, err := rec.Record(context.Background(), "eng", reachedDir, rawSubjects)
	if err != nil {
		t.Fatalf("record over reached graph: %v", err)
	}
	if minted != 1 {
		t.Fatalf("a raw npm subject reached through a first-party wrapper must mint 1 raise-only judgment, got %d", minted)
	}

	// Not reached: the package is imported but never called; raise-only mints nothing.
	uncalledDir := writeApp(t, "import { template } from 'lodash';\nfunction render(x) { return x; }\nrender('hi');\n")
	rec2, _ := NewInterprocRecorder(prodFactsProvider{}, &prodJudgments{}, prodAudit{}, prodClock{})
	minted2, err := rec2.Record(context.Background(), "eng", uncalledDir, rawSubjects)
	if err != nil {
		t.Fatalf("record over uncalled graph: %v", err)
	}
	if minted2 != 0 {
		t.Fatalf("an imported-but-uncalled package must mint nothing (raise-only), got %d", minted2)
	}
}
