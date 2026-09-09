package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const nugetLockFixture = `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
      "Serilog": {"type": "Transitive", "resolved": "2.12.0"},
      "MyApp.Core": {"type": "Project"}
    },
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
      "Polly": {"type": "Transitive", "resolved": "7.2.4"}
    }
  }
}`

func TestNuGetParse(t *testing.T) {
	comps, deps, err := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(nugetLockFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// This fixture's entries carry no `dependencies` sub-maps, so there is no graph to emit.
	if deps != nil {
		t.Errorf("no dependency sub-maps in fixture; want nil deps, got %v", deps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// Newtonsoft.Json (same version under both TFMs) dedups → 1; + Serilog + Polly = 3. The Project ref skipped.
	if len(comps) != 3 {
		t.Fatalf("want 3 components (Newtonsoft dedup, Project skipped), got %d (%+v)", len(comps), comps)
	}
	if _, ok := byName["MyApp.Core"]; ok {
		t.Error("a Project reference must not be emitted as a nuget package")
	}
	if c := byName["Newtonsoft.Json"]; c.PURL != "pkg:nuget/Newtonsoft.Json@13.0.1" {
		t.Errorf("PURL wrong: %+v", c)
	}
	if _, ok := byName["Polly"]; !ok {
		t.Error("a Transitive package must be emitted")
	}
}

func TestNuGetParseDeterministic(t *testing.T) {
	// packages.lock.json's per-framework maps have no inherent order; the parser sorts by PURL so the output
	// is stable across runs (Go randomizes map iteration).
	c1, _, _ := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(nugetLockFixture)})
	c2, _, _ := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(nugetLockFixture)})
	if len(c1) != len(c2) {
		t.Fatalf("length mismatch %d vs %d", len(c1), len(c2))
	}
	for i := range c1 {
		if c1[i].PURL != c2[i].PURL {
			t.Errorf("order not deterministic at %d: %q vs %q", i, c1[i].PURL, c2[i].PURL)
		}
	}
}

func TestNuGetParseMalformed(t *testing.T) {
	if _, _, err := (NuGet{}).Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte("{bad")}); err == nil {
		t.Error("malformed packages.lock.json must fail loud")
	}
}

// A packages.lock.json whose entries carry `dependencies` maps produces edges, each resolved to the concrete
// version restored under the same target framework (never the range), with Project/unresolved deps dropped.
func TestNuGetParseEdges(t *testing.T) {
	const lock = `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "AppRoot": {"type": "Project"},
      "Serilog.Sinks.File": {"type": "Direct", "resolved": "5.0.0", "dependencies": {"Serilog": "2.12.0", "AppRoot": "1.0.0", "Ghost": "9.9.9"}},
      "Serilog": {"type": "Transitive", "resolved": "2.12.0"}
    }
  }
}`
	comps, deps, err := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(lock)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 2 { // Serilog.Sinks.File + Serilog; AppRoot is a Project
		t.Fatalf("want 2 components, got %d (%+v)", len(comps), comps)
	}
	byRef := map[string][]string{}
	for _, d := range deps {
		byRef[d.Ref] = d.DependsOn
	}
	on := byRef["pkg:nuget/Serilog.Sinks.File@5.0.0"]
	// Serilog resolves (range 2.12.0 -> resolved 2.12.0); AppRoot is a Project (dropped); Ghost is not a
	// resolved package (dropped). So the only edge target is the concrete Serilog@2.12.0.
	if len(on) != 1 || on[0] != "pkg:nuget/Serilog@2.12.0" {
		t.Errorf("Serilog.Sinks.File edges = %v, want [pkg:nuget/Serilog@2.12.0]", on)
	}
	// PathToRoot: Serilog is transitive (Serilog.Sinks.File depends on it); Serilog.Sinks.File is direct.
	if p := sbom.PathToRoot(deps, "pkg:nuget/Serilog@2.12.0"); len(p) < 2 {
		t.Errorf("Serilog must be transitive, PathToRoot=%v", p)
	}
	if p := sbom.PathToRoot(deps, "pkg:nuget/Serilog.Sinks.File@5.0.0"); len(p) != 1 {
		t.Errorf("Serilog.Sinks.File must be a direct/top-level dep, PathToRoot=%v", p)
	}
}

// A dependency's range must resolve to the concrete version restored under the SAME framework, and edges are
// merged/deduped across frameworks by source PURL.
func TestNuGetParseEdgesCrossFramework(t *testing.T) {
	const lock = `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "A": {"type": "Direct", "resolved": "1.0.0", "dependencies": {"B": "2.0.0"}},
      "B": {"type": "Transitive", "resolved": "2.0.0"}
    },
    "net8.0": {
      "A": {"type": "Direct", "resolved": "1.0.0", "dependencies": {"B": "2.0.0", "C": "3.0.0"}},
      "B": {"type": "Transitive", "resolved": "2.0.0"},
      "C": {"type": "Transitive", "resolved": "3.0.0"}
    }
  }
}`
	_, deps, err := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(lock)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var on []string
	n := 0
	for _, d := range deps {
		if d.Ref == "pkg:nuget/A@1.0.0" {
			n++
			on = d.DependsOn
		}
	}
	if n != 1 {
		t.Fatalf("A@1.0.0 must have exactly one merged Dependency, got %d", n)
	}
	if !contains(on, "pkg:nuget/B@2.0.0") || !contains(on, "pkg:nuget/C@3.0.0") {
		t.Errorf("A edges merged across frameworks = %v, want B + C", on)
	}
}

// NuGet ids are case-insensitive: a dependency written with different casing than the resolved entry must
// still produce an edge, and the edge target uses the resolved entry's canonical casing.
func TestNuGetParseEdgesCaseInsensitive(t *testing.T) {
	const lock = `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Pkg.A": {"type": "Direct", "resolved": "1.0.0", "dependencies": {"newtonsoft.json": "[13.0.3, )"}},
      "Newtonsoft.Json": {"type": "Transitive", "resolved": "13.0.3"}
    }
  }
}`
	_, deps, err := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(lock)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var on []string
	for _, d := range deps {
		if d.Ref == "pkg:nuget/Pkg.A@1.0.0" {
			on = d.DependsOn
		}
	}
	if len(on) != 1 || on[0] != "pkg:nuget/Newtonsoft.Json@13.0.3" {
		t.Errorf("case-insensitive dep must resolve to the canonical Newtonsoft.Json@13.0.3, got %v", on)
	}
}

// A {TFM}/{RID} runtime section is a delta over the base TFM closure: an edge from a RID-only package to a
// base-TFM package must resolve via the base fallback.
func TestNuGetParseEdgesRIDOverlay(t *testing.T) {
	const lock = `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Base.Lib": {"type": "Transitive", "resolved": "1.0.0"}
    },
    "net8.0/win-x64": {
      "Native.Lib": {"type": "Transitive", "resolved": "2.0.0", "dependencies": {"Base.Lib": "[1.0.0, )"}}
    }
  }
}`
	_, deps, err := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(lock)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var on []string
	for _, d := range deps {
		if d.Ref == "pkg:nuget/Native.Lib@2.0.0" {
			on = d.DependsOn
		}
	}
	if len(on) != 1 || on[0] != "pkg:nuget/Base.Lib@1.0.0" {
		t.Errorf("RID package edge must resolve to the base-TFM package, got %v", on)
	}
}
