package nugetreach

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeScanner struct {
	graph ports.SourceImportGraph
	err   error
}

func (f fakeScanner) ScanImports(context.Context, string) (ports.SourceImportGraph, error) {
	return f.graph, f.err
}
func (fakeScanner) Lang() string { return "nuget" }

type fakeData struct {
	pkgs    map[string]ports.NuGetPackageNamespaces
	present bool
	err     error
}

func (f fakeData) LoadReachabilityData(context.Context, string, []string) (map[string]ports.NuGetPackageNamespaces, bool, error) {
	return f.pkgs, f.present, f.err
}

func direct(names ...string) DirectDependencyReader {
	return func(context.Context, string) (map[string]bool, bool) {
		m := map[string]bool{}
		for _, n := range names {
			m[n] = true
		}
		return m, true
	}
}

func mustAnalyzer(t *testing.T, s ports.SourceImportScanner, d ports.NuGetReachabilityData, dd DirectDependencyReader) *Analyzer {
	t.Helper()
	a, err := New(s, d, dd)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func resultFor(t *testing.T, a *Analyzer, symbols ...string) map[string]bool {
	t.Helper()
	an, err := a.Analyze(context.Background(), "/x", symbols)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	out := map[string]bool{}
	for _, r := range an.Results {
		out[r.Symbol] = r.Reachable
	}
	return out
}

// TestBuildAwareUsesRealNamespaces is the core fix: AWSSDK.S3 whose REAL namespace is Amazon.S3 is reported
// REACHABLE when source uses `Amazon.S3`, so the id/namespace mismatch never produces a false suppression;
// Serilog, whose real namespace nothing references, is proven unreachable.
func TestBuildAwareUsesRealNamespaces(t *testing.T) {
	scanner := fakeScanner{graph: ports.SourceImportGraph{ImportedPackages: []string{"amazon", "amazon.s3"}, FilesScanned: 1}}
	data := fakeData{present: true, pkgs: map[string]ports.NuGetPackageNamespaces{
		"awssdk.s3": {Namespaces: []string{"amazon.s3", "amazon.s3.model"}, Complete: true},
		"serilog":   {Namespaces: []string{"serilog"}, Complete: true},
	}}
	a := mustAnalyzer(t, scanner, data, direct("awssdk.s3", "serilog"))
	got := resultFor(t, a, "AWSSDK.S3", "Serilog")
	if !got["AWSSDK.S3"] {
		t.Error("AWSSDK.S3 uses namespace Amazon.S3 which source references; must be REACHABLE (no false suppression)")
	}
	if got["Serilog"] {
		t.Error("Serilog's namespace is never referenced; must be not-reachable")
	}
	if _, ok := got["Serilog"]; !ok {
		t.Error("Serilog must be decided (present in results as not-reachable)")
	}
}

func TestBuildAwareFailsClosedOnIncompleteObservation(t *testing.T) {
	scanner := fakeScanner{graph: ports.SourceImportGraph{
		ImportedPackages: []string{"system"},
		CoverageReasons:  []string{"reflection resolves a type from a runtime value"},
		FilesScanned:     1,
	}}
	data := fakeData{present: true, pkgs: map[string]ports.NuGetPackageNamespaces{"serilog": {Namespaces: []string{"serilog"}, Complete: true}}}
	a := mustAnalyzer(t, scanner, data, direct("serilog"))
	if _, err := a.Analyze(context.Background(), "/x", []string{"Serilog"}); err == nil {
		t.Error("a dynamic construct in source must fail closed (no coverage), never conclude unreachable")
	}
}

func TestBuildAwareFailsClosedWithoutRestoreGraph(t *testing.T) {
	scanner := fakeScanner{graph: ports.SourceImportGraph{ImportedPackages: []string{"system"}, FilesScanned: 1}}
	data := fakeData{present: false} // no project.assets.json
	a := mustAnalyzer(t, scanner, data, direct("serilog"))
	if _, err := a.Analyze(context.Background(), "/x", []string{"Serilog"}); err == nil {
		t.Error("no restore graph must fail closed (build-aware namespaces unknown)")
	}
}

func TestBuildAwareOmitsUnknownSubjects(t *testing.T) {
	scanner := fakeScanner{graph: ports.SourceImportGraph{ImportedPackages: []string{"system"}, FilesScanned: 1}}
	data := fakeData{present: true, pkgs: map[string]ports.NuGetPackageNamespaces{
		"known.complete":   {Namespaces: []string{"known"}, Complete: true},
		"known.incomplete": {Namespaces: []string{"foo"}, Complete: false},
		"known.empty":      {Namespaces: nil, Complete: true},
	}}
	// transitive.pkg is NOT a direct dependency.
	a := mustAnalyzer(t, scanner, data, direct("known.complete", "known.incomplete", "known.empty"))
	got := resultFor(t, a, "known.complete", "known.incomplete", "known.empty", "transitive.pkg")
	if _, ok := got["known.complete"]; !ok {
		t.Error("a direct dep with complete namespaces must be decided")
	}
	for _, omit := range []string{"known.incomplete", "known.empty", "transitive.pkg"} {
		if _, ok := got[omit]; ok {
			t.Errorf("%s must be OMITTED (unknown), so the coordinator leaves the prior tier standing", omit)
		}
	}
}

func TestAnyNamespaceObservedSymmetric(t *testing.T) {
	// Observed set NOT prefix-closed: only a sub-namespace of the package's namespace is present.
	if !anyNamespaceObserved([]string{"amazon.s3"}, map[string]bool{"amazon.s3.transfer": true}) {
		t.Error("an observed sub-namespace of the package namespace must count as a reference")
	}
	// Package namespace is a sub-namespace of an observed one.
	if !anyNamespaceObserved([]string{"amazon.s3.model"}, map[string]bool{"amazon.s3": true}) {
		t.Error("an observed parent namespace must count as a reference")
	}
	// No relation: not observed.
	if anyNamespaceObserved([]string{"serilog"}, map[string]bool{"system": true, "amazon.s3": true}) {
		t.Error("an unrelated namespace must not match")
	}
	// Empty package namespace must never match empty observed.
	if anyNamespaceObserved([]string{""}, map[string]bool{"": true}) {
		t.Error("empty namespaces must not match")
	}
}
