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

func TestNewInterprocConstructorsValidate(t *testing.T) {
	if _, err := NewInterprocAnalyzer(nil); err == nil {
		t.Error("nil provider must error")
	}
	if _, err := NewInterprocRecorder(nil, nil, nil, nil); err == nil {
		t.Error("nil deps must error")
	}
}
