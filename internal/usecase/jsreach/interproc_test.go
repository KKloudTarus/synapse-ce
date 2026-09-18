package jsreach

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jssymbols"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// wrapperGraph models: module app (entrypoint) -> render() -> lodash.template (external), plus a subpath
// call app -> get() -> lodash/fp.get, and an UNCALLED external node lodash.merge that no path reaches.
func wrapperGraph() jsprogram.Resolution {
	g := callgraph.Graph{
		Entrypoints: []string{"js:app:<module>"},
		Edges: []callgraph.Edge{
			{Caller: "js:app:<module>", Callees: []string{"js:app:render", "js:app:get"}},
			{Caller: "js:app:render", Callees: []string{jsprogram.ExternalSymbolID("lodash", "template")}},
			{Caller: "js:app:get", Callees: []string{jsprogram.ExternalSymbolID("lodash/fp", "get")}},
			// merge is defined by some unreached function; include the node on an edge from an unreached caller.
			{Caller: "js:app:dead", Callees: []string{jsprogram.ExternalSymbolID("lodash", "merge")}},
		},
	}
	return jsprogram.Resolution{Graph: g, Complete: true}
}

func evidenceFrom(res jsprogram.Resolution) interprocEvidence {
	return interprocEvidence{resolution: res, externalNodes: externalNodesOf(res)}
}

func TestFirstPartySymbolSubject(t *testing.T) {
	subject, ok := FirstPartySymbolSubject("src/main.mjs", "target")
	if !ok || subject != "js:src/main:target" {
		t.Fatalf("first-party source subject = %q/%v, want js:src/main:target/true", subject, ok)
	}
	for _, invalid := range []string{"package.json", "../app.mjs", "C:/app.mjs", ""} {
		if _, ok := FirstPartySymbolSubject(invalid, "target"); ok {
			t.Fatalf("FirstPartySymbolSubject(%q) accepted a non-source or unsafe module", invalid)
		}
	}
}

func TestSplitExternalID(t *testing.T) {
	cases := map[string]struct {
		id           string
		spec, export string
		ok           bool
	}{
		"named":                    {"jsnpm:lodash:template", "lodash", "template", true},
		"subpath":                  {"jsnpm:lodash/fp:get", "lodash/fp", "get", true},
		"scoped":                   {"jsnpm:@scope/pkg:foo", "@scope/pkg", "foo", true},
		"cjs member":               {"jsnpm:axios:default.get", "axios", "default.get", true},
		"first-party not external": {"js:app:render", "", "", false},
		"no export":                {"jsnpm:lodash:", "", "", false},
		"no spec":                  {"jsnpm::x", "", "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			spec, export, ok := splitExternalID(tc.id)
			if ok != tc.ok || spec != tc.spec || export != tc.export {
				t.Fatalf("splitExternalID(%q) = (%q,%q,%v), want (%q,%q,%v)", tc.id, spec, export, ok, tc.spec, tc.export, tc.ok)
			}
		})
	}
}

func TestExternalNodesOfCollectsOnlyExternal(t *testing.T) {
	nodes := externalNodesOf(wrapperGraph())
	if len(nodes) != 3 {
		t.Fatalf("expected 3 external nodes (template, fp.get, merge), got %d: %+v", len(nodes), nodes)
	}
	// First-party ids must never be collected as external.
	for _, n := range nodes {
		if n.specifier == "" || n.export == "" {
			t.Fatalf("malformed external node: %+v", n)
		}
	}
}

func TestReachMatchesPackageAndExport(t *testing.T) {
	ev := evidenceFrom(wrapperGraph())

	// A reached named external export.
	if _, path, ok := ev.reach("lodash", "template"); !ok || len(path) == 0 {
		t.Errorf("lodash#template must be reachable through the render wrapper, path=%v ok=%v", path, ok)
	}
	// A reached subpath import.
	if _, _, ok := ev.reach("lodash", "get"); !ok {
		t.Errorf("lodash#get must match the lodash/fp subpath external node and be reachable")
	}
	// Package-level match (no export named) fires on any reached call into the package.
	if _, _, ok := ev.reach("lodash", ""); !ok {
		t.Errorf("lodash (no export) must be reachable at package granularity")
	}
	// An export whose node exists but is only reached from a dead (unreached) caller is NOT reachable.
	if _, _, ok := ev.reach("lodash", "merge"); ok {
		t.Errorf("lodash#merge is only called from an unreached function and must not be reachable")
	}
	// A different package must not match lodash's nodes.
	if _, _, ok := ev.reach("express", "template"); ok {
		t.Errorf("express must not match a lodash external node")
	}
	// An export the package never calls is not reachable.
	if _, _, ok := ev.reach("lodash", "nonexistent"); ok {
		t.Errorf("an export with no matching external node must not be reachable")
	}
}

func TestExportMatches(t *testing.T) {
	if !exportMatches("template", "template") {
		t.Error("exact export must match")
	}
	if !exportMatches("default.get", "get") {
		t.Error("a CommonJS default-object member must match the bare export name")
	}
	if exportMatches("safeObj.vuln", "vuln") {
		t.Error("a deeper dotted member must NOT match a top-level export by suffix (would raise the wrong finding)")
	}
	if exportMatches("template", "merge") {
		t.Error("unrelated exports must not match")
	}
}

type fakeFactsProvider struct {
	doc       jsprogram.Document
	available bool
	err       error
}

func (f fakeFactsProvider) JsFacts(context.Context, string) (jsprogram.Document, bool, error) {
	return f.doc, f.available, f.err
}

func TestInterprocAnalyzeNoCoveragePaths(t *testing.T) {
	// A provider error is a no-coverage error (prior tier stands), not a false negative.
	a, _ := NewInterprocAnalyzer(fakeFactsProvider{err: errors.New("ast sidecar down")})
	if _, err := a.Analyze(context.Background(), "/repo", []string{"pkg:npm/lodash@4#template"}); err == nil {
		t.Error("a facts-provider error must surface as a no-coverage error")
	}
	// An unavailable sidecar is ErrNotFound (no coverage), never a silent negative.
	a2, _ := NewInterprocAnalyzer(fakeFactsProvider{available: false})
	if _, err := a2.Analyze(context.Background(), "/repo", []string{"pkg:npm/lodash@4#template"}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("an unavailable sidecar must be ErrNotFound, got %v", err)
	}
	// No subjects is a clean empty analysis.
	a3, _ := NewInterprocAnalyzer(fakeFactsProvider{available: true})
	if got, err := a3.Analyze(context.Background(), "/repo", nil); err != nil || got == nil || len(got.Results) != 0 {
		t.Errorf("empty subjects must return an empty analysis, got %+v err=%v", got, err)
	}
}

func TestEncodeNPMSubjects(t *testing.T) {
	subjects := []ports.ReachabilitySubject{
		// An npm finding with a raw affected symbol: encoded to pkg:npm/...#export, finding id preserved.
		{FindingID: "f-lodash", PackagePURL: "pkg:npm/lodash@4.17.20", Symbols: []string{"template", "template"}},
		// A non-npm finding (Go): dropped, another recorder answers it.
		{FindingID: "f-go", PackagePURL: "pkg:golang/github.com/x/y@1.2.3", Symbols: []string{"Foo"}},
		// No package identity: dropped.
		{FindingID: "f-nopurl", Symbols: []string{"bar"}},
		// A malformed npm identity: dropped rather than guessing a version.
		{FindingID: "f-invalid", PackagePURL: "pkg:npm/lodash", Symbols: []string{"template"}},
	}
	original := append([]ports.ReachabilitySubject(nil), subjects...)
	for index := range original {
		original[index].Symbols = append([]string(nil), subjects[index].Symbols...)
	}
	out := EncodeNPMSubjects(subjects)
	if !reflect.DeepEqual(subjects, original) {
		t.Fatalf("input mutated: got %+v want %+v", subjects, original)
	}
	if !reflect.DeepEqual(out, EncodeNPMSubjects(subjects)) {
		t.Fatalf("encoding is not deterministic: %+v", out)
	}
	if len(out) != 1 {
		t.Fatalf("expected only the npm subject to encode, got %d: %+v", len(out), out)
	}
	if out[0].FindingID != "f-lodash" {
		t.Fatalf("finding id must be preserved, got %q", out[0].FindingID)
	}
	if len(out[0].Symbols) != 1 || out[0].Symbols[0] != "pkg:npm/lodash@4.17.20#template" {
		t.Fatalf("expected one deduped encoded subject, got %+v", out[0].Symbols)
	}
	// The encoded subject must round-trip through the analyzer's own parser.
	if _, export, ok := jssymbols.ParseSubject(out[0].Symbols[0]); !ok || export != "template" {
		t.Fatalf("encoded subject must parse back to export template, got export=%q ok=%v", export, ok)
	}
}

// TestEncodeNPMSubjectsSkipsVersionAmbiguity pins that a package with findings on TWO installed versions is
// skipped entirely: the version-blind call graph cannot say which version a reached import resolves to, so
// raising either would be a wrong-version raise. The version-exact lexical tiers still stand.
func TestEncodeNPMSubjectsSkipsVersionAmbiguity(t *testing.T) {
	subjects := []ports.ReachabilitySubject{
		{FindingID: "f-v4", PackagePURL: "pkg:npm/lodash@4.17.20", Symbols: []string{"template"}},
		{FindingID: "f-v5", PackagePURL: "pkg:npm/lodash@5.0.0", Symbols: []string{"template"}},
		{FindingID: "f-express", PackagePURL: "pkg:npm/express@4.18.0", Symbols: []string{"use"}},
	}
	out := EncodeNPMSubjects(subjects)
	if len(out) != 1 || out[0].FindingID != "f-express" {
		t.Fatalf("both lodash versions must be skipped as ambiguous, only express encoded, got %+v", out)
	}
}

// injectEvidence bypasses Resolve so Analyze runs against a hand-built resolution (the constructor caches
// per-dir evidence; a same-package test can seed that cache directly).
func injectEvidence(t *testing.T, res jsprogram.Resolution) *InterprocAnalyzer {
	t.Helper()
	a, err := NewInterprocAnalyzer(fakeFactsProvider{available: true})
	if err != nil {
		t.Fatalf("NewInterprocAnalyzer: %v", err)
	}
	ev := evidenceFrom(res)
	a.cached, a.cachedDir = &ev, "/repo"
	return a
}

// TestAnalyzeEmitsSoundNegativeOnCompleteGraph: on a COMPLETE graph, an affected export with NO first-party
// call site at all yields a not-reachable verdict with NO blind constructs, so the coordinator can turn it
// into a suppression. An export that IS called but only from unreached code (an exported wrapper could invoke
// it) is tainted instead.
func TestAnalyzeEmitsSoundNegativeOnCompleteGraph(t *testing.T) {
	a := injectEvidence(t, wrapperGraph()) // Complete: true; nonexistent has no external node
	analysis, err := a.Analyze(context.Background(), "/repo", []string{"pkg:npm/lodash@4#nonexistent"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Reachable {
		t.Fatalf("an unreached export must yield exactly one not-reachable result, got %+v", analysis.Results)
	}
	if len(analysis.BlindConstructs) != 0 {
		t.Fatalf("a complete graph must carry no blind constructs, got %v", analysis.BlindConstructs)
	}
	if len(analysis.Results[0].BlindConstructs) != 0 {
		t.Fatalf("a never-called export on a complete, non-escaping graph must carry no per-symbol blind constructs, got %v", analysis.Results[0].BlindConstructs)
	}
	// merge HAS a call site (from the unreached js:app:dead) so its negative is tainted: an exported wrapper
	// could reach it, so absence of a path from declared entry points is not a sound proof of absence.
	called, _ := a.Analyze(context.Background(), "/repo", []string{"pkg:npm/lodash@4#merge"})
	if len(called.Results) != 1 || called.Results[0].Reachable ||
		len(called.Results[0].BlindConstructs) != 1 || called.Results[0].BlindConstructs[0] != "jsprogram:export_call_unreached" {
		t.Fatalf("a called-but-unreached export must be tainted export_call_unreached, got %+v", called.Results)
	}
	// A reached export in the same complete graph is a positive with a path.
	pos, _ := a.Analyze(context.Background(), "/repo", []string{"pkg:npm/lodash@4#template"})
	if len(pos.Results) != 1 || !pos.Results[0].Reachable || len(pos.Results[0].Path) == 0 {
		t.Fatalf("a reached export must be positive with a proof path, got %+v", pos.Results)
	}
}

// TestAnalyzeIncompleteGraphTaintsNegative: on an INCOMPLETE graph, an unreached export still yields a
// not-reachable verdict, but the analysis carries blind constructs derived from the gaps, which the
// coordinator folds into the claim so ProvedNotReachable is false and the finding is never suppressed.
func TestAnalyzeIncompleteGraphTaintsNegative(t *testing.T) {
	res := wrapperGraph()
	res.Complete = false
	res.Gaps = []jsprogram.CoverageGap{
		{Kind: jsprogram.GapUnresolvedCall, SymbolID: "js:app:render", Detail: "callback_escape"},
		{Kind: jsprogram.GapDynamicImport, SymbolID: "js:app:<module>", Detail: "dynamic_import"},
	}
	a := injectEvidence(t, res)
	analysis, err := a.Analyze(context.Background(), "/repo", []string{"pkg:npm/lodash@4#merge"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Reachable {
		t.Fatalf("unreached export must still be not-reachable, got %+v", analysis.Results)
	}
	want := map[string]bool{"jsprogram:unresolved_call": true, "jsprogram:dynamic_import": true}
	if len(analysis.BlindConstructs) != len(want) {
		t.Fatalf("incomplete graph must surface its gap kinds as blind constructs, got %v", analysis.BlindConstructs)
	}
	for _, bc := range analysis.BlindConstructs {
		if !want[bc] {
			t.Errorf("unexpected blind construct %q", bc)
		}
	}
}

// TestAnalyzeIncompleteWithNoGapsStillTaints: a resolution flagged incomplete with an empty gap list (a
// truncated extraction) must still taint negatives with a generic marker, never present them as sound.
func TestAnalyzeIncompleteWithNoGapsStillTaints(t *testing.T) {
	res := wrapperGraph()
	res.Complete = false
	res.Gaps = nil
	a := injectEvidence(t, res)
	analysis, _ := a.Analyze(context.Background(), "/repo", []string{"pkg:npm/lodash@4#merge"})
	if len(analysis.BlindConstructs) != 1 || analysis.BlindConstructs[0] != "jsprogram:incomplete" {
		t.Fatalf("an incomplete graph with no explicit gap must still taint negatives, got %v", analysis.BlindConstructs)
	}
}

func TestEscapedImportSpecifiers(t *testing.T) {
	doc := jsprogram.Document{
		Imports: []jsprogram.Import{
			{Module: "pkg", Alias: "vuln"},
			{Module: "safe", Alias: "ok"},
			{Module: "lodash", Alias: "_"},                         // only ever a call base below, never a value
			{Module: "reexported", Kind: jsprogram.ImportReexport}, // export ... from 'reexported'
		},
		Calls: []jsprogram.Call{
			// vuln passed as an argument -> pkg escapes; _.each(...) uses _ as a call base, not a value.
			{Arguments: []jsprogram.Argument{{Value: jsprogram.Reference{Segments: []string{"vuln"}}}}},
		},
		Returns: []jsprogram.Return{
			{Value: jsprogram.Reference{Segments: []string{"ok"}}}, // ok returned -> safe escapes
		},
	}
	got := escapedImportSpecifiers(doc)
	want := map[string]bool{"pkg": true, "safe": true, "reexported": true}
	if len(got) != len(want) {
		t.Fatalf("escaped specifiers = %v; want pkg, safe, reexported", got)
	}
	for _, s := range got {
		if !want[s] {
			t.Errorf("unexpected escaped specifier %q (lodash used only as a call base must not escape)", s)
		}
	}
}

// TestAnalyzeTaintsEscapedPackageNegative pins that an unreached export of a package whose binding escapes is
// NOT a sound negative: the per-symbol blind construct keeps it from suppressing, even on a complete graph.
func TestAnalyzeTaintsEscapedPackageNegative(t *testing.T) {
	ev := evidenceFrom(wrapperGraph()) // Complete: true, no analysis-wide blind constructs
	ev.escapedSpecifiers = []string{"lodash"}
	a, _ := NewInterprocAnalyzer(fakeFactsProvider{available: true})
	a.cached, a.cachedDir = &ev, "/repo"

	analysis, err := a.Analyze(context.Background(), "/repo", []string{"pkg:npm/lodash@4#merge"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Reachable {
		t.Fatalf("expected one not-reachable result, got %+v", analysis.Results)
	}
	if len(analysis.Results[0].BlindConstructs) == 0 {
		t.Fatal("an escaped package's negative must carry a blind construct so it cannot suppress")
	}
	// The analysis-wide blind set stays empty (the graph is Complete); only THIS symbol is tainted.
	if len(analysis.BlindConstructs) != 0 {
		t.Fatalf("a complete graph must carry no analysis-wide blind constructs, got %v", analysis.BlindConstructs)
	}
}

func TestWithSuppressionToggles(t *testing.T) {
	r := &InterprocRecorder{}
	if r.suppress {
		t.Fatal("suppression must default off")
	}
	if r.WithSuppression(true); !r.suppress {
		t.Fatal("WithSuppression(true) must enable suppression")
	}
	if r.WithSuppression(false); r.suppress {
		t.Fatal("WithSuppression(false) must disable suppression")
	}
}

func TestNewInterprocConstructorsValidate(t *testing.T) {
	if _, err := NewInterprocAnalyzer(nil); err == nil {
		t.Error("nil provider must error")
	}
	if _, err := NewInterprocRecorder(nil, nil, nil, nil); err == nil {
		t.Error("nil deps must error")
	}
}
