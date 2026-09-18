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

// TestInterprocRecorderSuppressesUnreachedExportWithFlag is the #1139 acceptance at the production path: with
// the suppressing direction enabled, an imported-but-uncalled affected npm export on a COMPLETE call graph
// (with a real top-level entry point) mints a not-reachable Tier-2 judgment that SOUNDLY suppresses its
// finding; the same input with the default raise-only recorder mints nothing (proven by the test above).
func TestInterprocRecorderSuppressesUnreachedExportWithFlag(t *testing.T) {
	rawSubjects := []ports.ReachabilitySubject{
		{FindingID: "f-lodash", PackagePURL: "pkg:npm/lodash@4.17.20", Symbols: []string{"template"}},
	}
	// lodash.template is imported but never called; render() is called at module top level, so the graph has a
	// real entry point and no dynamic construct — a complete graph in which template is provably unreached.
	uncalledDir := writeApp(t, "import { template } from 'lodash';\nfunction render(x) { return x; }\nrender('hi');\n")

	judgments := &prodJudgments{}
	rec, err := NewInterprocRecorder(prodFactsProvider{}, judgments, prodAudit{}, prodClock{})
	if err != nil {
		t.Fatal(err)
	}
	rec.WithSuppression(true)
	minted, err := rec.Record(context.Background(), "eng", uncalledDir, rawSubjects)
	if err != nil {
		t.Fatalf("record with suppression: %v", err)
	}
	if minted != 1 {
		t.Fatalf("suppression on: an unreached export on a complete graph must mint 1 not-reachable judgment, got %d", minted)
	}
	rc, ok := judgments.items[len(judgments.items)-1].Claim.(judgment.ReachabilityClaim)
	if !ok {
		t.Fatalf("minted claim is not a ReachabilityClaim: %+v", judgments.items)
	}
	if rc.Reachable != judgment.NotReachable {
		t.Fatalf("suppression must mint a NotReachable claim, got %v", rc.Reachable)
	}
	if !rc.SuppressesFinding() {
		t.Fatalf("the not-reachable claim must soundly suppress (proved not-reachable + entry points present), got %+v", rc)
	}
}

// lastClaim returns the reachability claim of the most recently minted judgment.
func lastClaim(t *testing.T, judgments *prodJudgments) judgment.ReachabilityClaim {
	t.Helper()
	if len(judgments.items) == 0 {
		t.Fatal("no judgment was minted")
	}
	rc, ok := judgments.items[len(judgments.items)-1].Claim.(judgment.ReachabilityClaim)
	if !ok {
		t.Fatalf("minted claim is not a ReachabilityClaim: %+v", judgments.items)
	}
	return rc
}

// TestInterprocRecorderDoesNotSuppressOnDynamicConstruct guards the soundness gate at the production path: a
// computed member access makes the resolver graph incomplete, so even with suppression ENABLED the minted
// not-reachable claim carries the graph's blind constructs and does NOT suppress the finding.
func TestInterprocRecorderDoesNotSuppressOnDynamicConstruct(t *testing.T) {
	rawSubjects := []ports.ReachabilitySubject{
		{FindingID: "f-lodash", PackagePURL: "pkg:npm/lodash@4.17.20", Symbols: []string{"template"}},
	}
	dynamicDir := writeApp(t, "import { template } from 'lodash';\nfunction render(o, k) { return o[k](); }\nrender({}, 'x');\n")
	judgments := &prodJudgments{}
	rec, _ := NewInterprocRecorder(prodFactsProvider{}, judgments, prodAudit{}, prodClock{})
	rec.WithSuppression(true)
	if _, err := rec.Record(context.Background(), "eng", dynamicDir, rawSubjects); err != nil {
		t.Fatalf("record over dynamic graph: %v", err)
	}
	if rc := lastClaim(t, judgments); rc.SuppressesFinding() {
		t.Fatalf("an incomplete graph (dynamic dispatch) must not soundly suppress even with the flag on, got %+v", rc)
	}
}

// TestInterprocRecorderDoesNotSuppressEscapedBinding is the soundness guard the resolver's Complete flag does
// NOT provide: the affected export is passed as an argument to a third-party higher-order function that can
// invoke it out of view of the static graph. The graph stays Complete (the escaped value is third-party), so
// without the import-escape guard this would unsoundly suppress a reachable vulnerability. The minted claim
// must not suppress.
func TestInterprocRecorderDoesNotSuppressEscapedBinding(t *testing.T) {
	rawSubjects := []ports.ReachabilitySubject{
		{FindingID: "f-pkg", PackagePURL: "pkg:npm/pkg@1.0.0", Symbols: []string{"vuln"}},
	}
	// vuln is passed to lodash.each, a higher-order library function that calls its callback: vuln IS reachable
	// at runtime, even though the static graph has no resolved call into vuln.
	escapeDir := writeApp(t, "import { vuln } from 'pkg';\nimport _ from 'lodash';\n_.each([1], vuln);\n")
	judgments := &prodJudgments{}
	rec, _ := NewInterprocRecorder(prodFactsProvider{}, judgments, prodAudit{}, prodClock{})
	rec.WithSuppression(true)
	if _, err := rec.Record(context.Background(), "eng", escapeDir, rawSubjects); err != nil {
		t.Fatalf("record over escape graph: %v", err)
	}
	if rc := lastClaim(t, judgments); rc.SuppressesFinding() {
		t.Fatalf("an escaped affected binding must not be suppressed, got %+v", rc)
	}
}

// TestInterprocRecorderDoesNotSuppressBareDecorator guards the extractor-level hole: an affected export applied
// as a BARE decorator runs at class-definition time (reachable), but the extractor models it as neither a call
// nor a value. The extractor now records a coverage gap for the bare decorator, so the graph is incomplete and
// no minted claim may suppress even with the flag on.
func TestInterprocRecorderDoesNotSuppressBareDecorator(t *testing.T) {
	rawSubjects := []ports.ReachabilitySubject{
		{FindingID: "f-mobx", PackagePURL: "pkg:npm/mobx@6.0.0", Symbols: []string{"observable"}},
	}
	decoratorDir := writeApp(t, "import { observable } from 'mobx';\nclass Store { @observable count = 0; }\nnew Store();\n")
	judgments := &prodJudgments{}
	rec, _ := NewInterprocRecorder(prodFactsProvider{}, judgments, prodAudit{}, prodClock{})
	rec.WithSuppression(true)
	if _, err := rec.Record(context.Background(), "eng", decoratorDir, rawSubjects); err != nil {
		t.Fatalf("record over decorator graph: %v", err)
	}
	for _, item := range judgments.items {
		if rc, ok := item.Claim.(judgment.ReachabilityClaim); ok && rc.SuppressesFinding() {
			t.Fatalf("a bare-decorator use of an affected export must not be suppressed, got %+v", rc)
		}
	}
}

// recorderSuppresses records with the suppressing direction on and reports whether any minted claim soundly
// suppresses the finding for pkg#vuln.
func recorderSuppresses(t *testing.T, src string) bool {
	t.Helper()
	dir := writeApp(t, src)
	judgments := &prodJudgments{}
	rec, _ := NewInterprocRecorder(prodFactsProvider{}, judgments, prodAudit{}, prodClock{})
	rec.WithSuppression(true)
	if _, err := rec.Record(context.Background(), "eng", dir, []ports.ReachabilitySubject{
		{FindingID: "f-pkg", PackagePURL: "pkg:npm/pkg@1.0.0", Symbols: []string{"vuln"}},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	for _, item := range judgments.items {
		if rc, ok := item.Claim.(judgment.ReachabilityClaim); ok && rc.SuppressesFinding() {
			return true
		}
	}
	return false
}

// TestInterprocRecorderReexposureNeverSuppresses is the comprehensive soundness table: every form that
// re-exposes or captures the affected import binding as a VALUE (so a consumer or a library callback could
// invoke it out of view of the static call graph) must NOT suppress the finding, on an otherwise-complete
// graph, with the flag on. These are the forms three rounds of adversarial review surfaced; the guard is
// position-based (any non-call-callee use of the binding taints its package), so it covers the class rather
// than each construct. The legitimately-suppressible case (imported but never used at all) is asserted to
// still suppress, so the guard is not a blanket disable.
func TestInterprocRecorderReexposureNeverSuppresses(t *testing.T) {
	unsound := map[string]string{
		"local-reexport":      "import { vuln } from 'pkg';\nexport { vuln };\n",
		"reexport-alias":      "import { vuln } from 'pkg';\nexport { vuln as v2 };\n",
		"export-default-id":   "import { vuln } from 'pkg';\nexport default vuln;\n",
		"export-default-obj":  "import { vuln } from 'pkg';\nexport default { handler: vuln };\n",
		"export-default-arr":  "import { vuln } from 'pkg';\nexport default [vuln];\n",
		"export-default-deep": "import { vuln } from 'pkg';\nexport default { a: { b: vuln } };\n",
		"object-shorthand":    "import { vuln } from 'pkg';\nmodule.exports = { vuln };\n",
		"export-const-obj":    "import { vuln } from 'pkg';\nexport const api = { vuln };\n",
		"nested-in-object":    "import { vuln } from 'pkg';\nconst o = { handler: vuln };\nexport default o;\n",
		"default-parameter":   "import { vuln } from 'pkg';\nexport function f(cb = vuln){ return cb; }\nf();\n",
		"class-field-init":    "import { vuln } from 'pkg';\nexport class C { h = vuln; }\nnew C();\n",
		"escaped-callback":    "import { vuln } from 'pkg';\nimport _ from 'lodash';\n_.each([1], vuln);\n",
		"return-value":        "import { vuln } from 'pkg';\nexport function get(){ return vuln; }\nget();\n",
	}
	for name, src := range unsound {
		if recorderSuppresses(t, src) {
			t.Errorf("%s: a re-exposed/captured affected binding must NOT be suppressed", name)
		}
	}
	if !recorderSuppresses(t, "import { vuln } from 'pkg';\nfunction r(x){ return x; }\nr(1);\n") {
		t.Error("a genuinely-unused affected import must still be suppressed (the guard must not blanket-disable)")
	}
}

// TestInterprocRecorderExportedWrapperNeverSuppresses guards the entry-surface hole: an affected export CALLED
// from a first-party function that is EXPORTED (a library public API or a framework-invoked export) is
// reachable to a consumer even though no in-tree top-level code calls the wrapper, so the declared entry-point
// set under-approximates reachability. A call site that exists but is not reached from a declared entry point
// is not a sound proof of absence and must not suppress; only an affected export with NO first-party call site
// at all may.
func TestInterprocRecorderExportedWrapperNeverSuppresses(t *testing.T) {
	unsound := map[string]string{
		"export-function":     "import { vuln } from 'pkg';\nexport function wrap(){ vuln(); }\n",
		"export-default-func": "import { vuln } from 'pkg';\nexport default function(){ vuln(); }\n",
		"export-arrow":        "import { vuln } from 'pkg';\nexport const h = () => vuln();\n",
		"export-brace":        "import { vuln } from 'pkg';\nfunction wrap(){ vuln(); }\nexport { wrap };\n",
		"cjs-export-func":     "import { vuln } from 'pkg';\nmodule.exports.run = function(){ vuln(); };\n",
		"exported-class":      "import { vuln } from 'pkg';\nexport class C { m(){ vuln(); } }\n",
	}
	for name, src := range unsound {
		if recorderSuppresses(t, src) {
			t.Errorf("%s: an affected export reachable via an exported wrapper must NOT be suppressed", name)
		}
	}
}
