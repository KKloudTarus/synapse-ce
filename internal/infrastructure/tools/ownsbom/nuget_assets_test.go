package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// TestNuGetAssetsParseEdges covers EPIC #860 D3.7: project.assets.json (the always-produced restore graph)
// yields components and resolved transitive edges. A dependency range resolves to the concrete "<Name>/<Version>"
// entry in the same framework; a "project" entry and an unresolved dependency are dropped.
func TestNuGetAssetsParseEdges(t *testing.T) {
	const assets = `{
  "version": 3,
  "targets": {
    "net8.0": {
      "Serilog.Sinks.File/5.0.0": {"type": "package", "dependencies": {"Serilog": "2.12.0", "Ghost": "9.9.9"}},
      "Serilog/2.12.0": {"type": "package"},
      "AppRoot/1.0.0": {"type": "project"}
    }
  }
}`
	comps, deps, err := NuGetAssets{}.Parse(context.Background(), ParseInput{Path: "obj/project.assets.json", Content: []byte(assets)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 2 { // Serilog.Sinks.File + Serilog; AppRoot is a project entry
		t.Fatalf("want 2 components, got %d (%+v)", len(comps), comps)
	}
	byRef := map[string][]string{}
	for _, d := range deps {
		byRef[d.Ref] = d.DependsOn
	}
	on := byRef["pkg:nuget/Serilog.Sinks.File@5.0.0"]
	// Serilog resolves (range 2.12.0 -> the "Serilog/2.12.0" entry); Ghost is not a resolved package (dropped).
	if len(on) != 1 || on[0] != "pkg:nuget/Serilog@2.12.0" {
		t.Errorf("edges = %v, want [pkg:nuget/Serilog@2.12.0]", on)
	}
	if p := sbom.PathToRoot(deps, "pkg:nuget/Serilog@2.12.0"); len(p) < 2 {
		t.Errorf("Serilog must be transitive, PathToRoot=%v", p)
	}
}

// TestNuGetAssetsNoGraphEmitsComponentsNoEdges: a restore graph whose packages declare no dependencies yields
// the components (inventory) but no edges, never a synthesized graph.
func TestNuGetAssetsNoGraphEmitsComponentsNoEdges(t *testing.T) {
	const assets = `{"version":3,"targets":{"net8.0":{"Newtonsoft.Json/13.0.1":{"type":"package"}}}}`
	comps, deps, err := NuGetAssets{}.Parse(context.Background(), ParseInput{Path: "obj/project.assets.json", Content: []byte(assets)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 1 || comps[0].PURL != "pkg:nuget/Newtonsoft.Json@13.0.1" {
		t.Fatalf("want the single package, got %+v", comps)
	}
	if len(deps) != 0 {
		t.Fatalf("no dependencies declared, so no edges must be emitted, got %+v", deps)
	}
}

func TestNuGetAssetsMalformed(t *testing.T) {
	if _, _, err := (NuGetAssets{}).Parse(context.Background(), ParseInput{Path: "project.assets.json", Content: []byte("{not json")}); err == nil {
		t.Fatal("malformed project.assets.json must error")
	}
}
