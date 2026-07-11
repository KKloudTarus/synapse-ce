package ownsbom

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Conan 2.x: reference strings under requires / build_requires / python_requires.
const conanLockV2Fixture = `{
  "version": "0.5",
  "requires": [
    "zlib/1.2.13#dd1f9f9e73f5c3d0e9e7f5c8a1234567",
    "openssl/3.1.0@_/_#abcdef"
  ],
  "build_requires": [
    "cmake/3.27.0"
  ],
  "python_requires": [
    "config/2.0@company/stable"
  ]
}`

// Conan 1.x: a graph_lock whose node ref fields carry the same reference strings.
const conanLockV1Fixture = `{
  "version": "0.4",
  "graph_lock": {
    "nodes": {
      "0": {"ref": "app/1.0"},
      "1": {"ref": "boost/1.83.0#rev123"}
    }
  }
}`

func parseConanTest(t *testing.T, path string, content []byte) ([]sbom.Component, []sbom.Dependency) {
	t.Helper()
	comps, deps, err := Conan{}.Parse(context.Background(), ParseInput{Path: path, Content: content})
	if err != nil {
		t.Fatalf("parse Conan fixture: %v", err)
	}
	return comps, deps
}

func TestConanParseV2(t *testing.T) {
	comps, deps, err := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV2Fixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("edges not emitted; want nil deps, got %v", deps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	if len(comps) != 4 {
		t.Fatalf("want 4 components (zlib, openssl, cmake, config), got %d (%+v)", len(comps), comps)
	}
	if c := byName["zlib"]; c.PURL != "pkg:conan/zlib@1.2.13" {
		t.Errorf("zlib PURL wrong (revision must be stripped): %+v", c)
	}
	if c := byName["zlib"]; c.Scope != sbom.ScopeProduction {
		t.Errorf("zlib scope wrong: %+v", c)
	}
	if c := byName["openssl"]; c.Version != "3.1.0" {
		t.Errorf("openssl version wrong (user/channel + revision must be stripped): %+v", c)
	}
	if c := byName["config"]; c.Scope != sbom.ScopeDevelopment {
		t.Errorf("config scope wrong: %+v", c)
	}
}

func TestConanParseV1(t *testing.T) {
	comps, _, err := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV1Fixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	if len(comps) != 2 {
		t.Fatalf("want 2 components (app, boost), got %d (%+v)", len(comps), comps)
	}
	if c := byName["boost"]; c.PURL != "pkg:conan/boost@1.83.0" {
		t.Errorf("boost PURL wrong: %+v", c)
	}
}

func TestConanParseDeterministic(t *testing.T) {
	// The 1.x graph_lock nodes map has no inherent order; the parser sorts by PURL for stable output.
	c1, _, _ := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV1Fixture)})
	c2, _, _ := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV1Fixture)})
	if len(c1) != len(c2) {
		t.Fatalf("length mismatch %d vs %d", len(c1), len(c2))
	}
	for i := range c1 {
		if c1[i].PURL != c2[i].PURL {
			t.Errorf("order not deterministic at %d: %q vs %q", i, c1[i].PURL, c2[i].PURL)
		}
	}
}

func TestConanParseMalformed(t *testing.T) {
	if _, _, err := (Conan{}).Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte("{bad")}); err == nil {
		t.Error("malformed conan.lock must fail loud")
	}
}

const conanLockV1GraphFixture = `{
  "version": "0.4",
  "graph_lock": {
    "nodes": {
      "4": {
        "ref": "openssl/3.0.0"
      },
      "2": {
        "ref": "lib-b/3.0"
      },
      "0": {
        "ref": "app/1.0",
        "requires": ["2", "1"],
        "build_requires": ["3"]
      },
      "3": {
        "ref": "cmake/3.29.0"
      },
      "1": {
        "ref": "lib-a/2.0",
        "requires": ["4"]
      }
    }
  }
}`

func TestConanParseV1GraphEdges(t *testing.T) {
	comps, deps, err := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV1GraphFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	expectedComps := []string{
		"pkg:conan/app@1.0",
		"pkg:conan/cmake@3.29.0",
		"pkg:conan/lib-a@2.0",
		"pkg:conan/lib-b@3.0",
		"pkg:conan/openssl@3.0.0",
	}
	if len(comps) != len(expectedComps) {
		t.Fatalf("want %d components, got %d", len(expectedComps), len(comps))
	}
	for i, purl := range expectedComps {
		if comps[i].PURL != purl {
			t.Errorf("comp %d: want %s, got %s", i, purl, comps[i].PURL)
		}
	}

	if len(deps) != 2 {
		t.Fatalf("want 2 dependencies, got %d: %+v", len(deps), deps)
	}

	if deps[0].Ref != "pkg:conan/app@1.0" {
		t.Errorf("dep 0 ref want pkg:conan/app@1.0, got %s", deps[0].Ref)
	}
	if len(deps[0].DependsOn) != 3 || deps[0].DependsOn[0] != "pkg:conan/cmake@3.29.0" || deps[0].DependsOn[1] != "pkg:conan/lib-a@2.0" || deps[0].DependsOn[2] != "pkg:conan/lib-b@3.0" {
		t.Errorf("dep 0 DependsOn wrong: %v", deps[0].DependsOn)
	}

	if deps[1].Ref != "pkg:conan/lib-a@2.0" {
		t.Errorf("dep 1 ref want pkg:conan/lib-a@2.0, got %s", deps[1].Ref)
	}
	if len(deps[1].DependsOn) != 1 || deps[1].DependsOn[0] != "pkg:conan/openssl@3.0.0" {
		t.Errorf("dep 1 DependsOn wrong: %v", deps[1].DependsOn)
	}
}

func TestConanParseV1GraphEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		wantComps []string
		wantDeps  []sbom.Dependency
	}{
		{
			name: "duplicate and missing targets",
			fixture: `{
			  "version": "0.4",
			  "graph_lock": {
			    "nodes": {
			      "1": { "ref": "app/1.0", "requires": ["2", "2", "404", "3", "1"], "build_requires": ["4"] },
			      "2": { "ref": "leaf/1.0" },
			      "3": { "ref": "invalid-reference" },
			      "4": { "ref": "leaf/1.0", "requires": ["5"], "context": "build" },
			      "5": { "ref": "toolchain/2.0" }
			    }
			  }
			}`,
			wantComps: []string{"pkg:conan/app@1.0", "pkg:conan/leaf@1.0", "pkg:conan/toolchain@2.0"},
			wantDeps: []sbom.Dependency{
				{Ref: "pkg:conan/app@1.0", DependsOn: []string{"pkg:conan/leaf@1.0"}},
				{Ref: "pkg:conan/leaf@1.0", DependsOn: []string{"pkg:conan/toolchain@2.0"}},
			},
		},
		{
			name: "duplicate source identity union",
			fixture: `{
			  "version": "0.4",
			  "graph_lock": {
			    "nodes": {
			      "1": { "ref": "protobuf/3.21.0", "requires": ["3"], "context": "host" },
			      "2": { "ref": "protobuf/3.21.0", "requires": ["4"], "context": "build" },
			      "3": { "ref": "abseil/20240116.0" },
			      "4": { "ref": "cmake/3.29.0" }
			    }
			  }
			}`,
			wantComps: []string{"pkg:conan/abseil@20240116.0", "pkg:conan/cmake@3.29.0", "pkg:conan/protobuf@3.21.0"},
			wantDeps: []sbom.Dependency{
				{Ref: "pkg:conan/protobuf@3.21.0", DependsOn: []string{"pkg:conan/abseil@20240116.0", "pkg:conan/cmake@3.29.0"}},
			},
		},
		{
			name: "collapsed self edge",
			fixture: `{
			  "version": "0.4",
			  "graph_lock": {
			    "nodes": {
			      "1": { "ref": "protobuf/3.21.0", "build_requires": ["2"], "context": "host" },
			      "2": { "ref": "protobuf/3.21.0", "context": "build" }
			    }
			  }
			}`,
			wantComps: []string{"pkg:conan/protobuf@3.21.0"},
			wantDeps:  nil,
		},
		{
			name: "ref-less root",
			fixture: `{
			  "version": "0.4",
			  "graph_lock": {
			    "nodes": {
			      "0": { "path": "/project/conanfile.txt", "requires": ["1", "2"] },
			      "1": { "ref": "zlib/1.3.1", "requires": ["3"] },
			      "2": { "ref": "openssl/3.2.1" },
			      "3": { "ref": "minizip/1.3" }
			    }
			  }
			}`,
			wantComps: []string{"pkg:conan/minizip@1.3", "pkg:conan/openssl@3.2.1", "pkg:conan/zlib@1.3.1"},
			wantDeps: []sbom.Dependency{
				{Ref: "pkg:conan/zlib@1.3.1", DependsOn: []string{"pkg:conan/minizip@1.3"}},
			},
		},
		{
			name: "python requires emitted as components only",
			fixture: `{
			  "version": "0.4",
			  "graph_lock": {
			    "nodes": {
			      "0": { "ref": "app/1.0", "requires": ["1"], "python_requires": ["pyreq/2.0@company/stable"] },
			      "1": { "ref": "lib/3.0" }
			    }
			  }
			}`,
			wantComps: []string{"pkg:conan/app@1.0", "pkg:conan/lib@3.0", "pkg:conan/pyreq@2.0"},
			wantDeps: []sbom.Dependency{
				{Ref: "pkg:conan/app@1.0", DependsOn: []string{"pkg:conan/lib@3.0"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comps, deps, err := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(tt.fixture)})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(comps) != len(tt.wantComps) {
				t.Fatalf("want %d comps, got %d: %+v", len(tt.wantComps), len(comps), comps)
			}
			for i, purl := range tt.wantComps {
				if comps[i].PURL != purl {
					t.Errorf("comp %d: want %s, got %s", i, purl, comps[i].PURL)
				}
			}
			if len(deps) != len(tt.wantDeps) {
				t.Fatalf("want %d deps, got %d: %+v", len(tt.wantDeps), len(deps), deps)
			}
			for i, d := range tt.wantDeps {
				if deps[i].Ref != d.Ref {
					t.Errorf("dep %d: want ref %s, got %s", i, d.Ref, deps[i].Ref)
				}
				if len(deps[i].DependsOn) != len(d.DependsOn) {
					t.Errorf("dep %d: want %d targets, got %d", i, len(d.DependsOn), len(deps[i].DependsOn))
				} else {
					for j, target := range d.DependsOn {
						if deps[i].DependsOn[j] != target {
							t.Errorf("dep %d target %d: want %s, got %s", i, j, target, deps[i].DependsOn[j])
						}
					}
				}
			}
		})
	}
}

func TestConanParseV1GraphEndpointsExistAsComponents(t *testing.T) {
	comps, deps, err := Conan{}.Parse(context.Background(), ParseInput{
		Path: "conan.lock",
		Content: []byte(`{
			"version": "0.4",
			"graph_lock": {
				"nodes": {
					"1": { "ref": "app/1.0", "requires": ["2", "404", "3"] },
					"2": { "ref": "leaf/1.0" },
					"3": { "ref": "invalid-reference" }
				}
			}
		}`),
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	componentIDs := map[string]bool{}
	for _, c := range comps {
		componentIDs[c.PURL] = true
	}

	for _, dep := range deps {
		if !componentIDs[dep.Ref] {
			t.Errorf("dep Ref %s missing from components", dep.Ref)
		}
		for _, target := range dep.DependsOn {
			if !componentIDs[target] {
				t.Errorf("dep target %s missing from components", target)
			}
		}
	}
}

func TestConanParseV1GraphPathToRoot(t *testing.T) {
	_, deps, err := Conan{}.Parse(context.Background(), ParseInput{Path: "conan.lock", Content: []byte(conanLockV1GraphFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	path := sbom.PathToRoot(deps, "pkg:conan/openssl@3.0.0")
	expected := []string{
		"pkg:conan/app@1.0",
		"pkg:conan/lib-a@2.0",
		"pkg:conan/openssl@3.0.0",
	}

	if len(path) != len(expected) {
		t.Fatalf("PathToRoot length want %d, got %d: %v", len(expected), len(path), path)
	}
	for i, p := range expected {
		if path[i] != p {
			t.Errorf("path %d: want %s, got %s", i, p, path[i])
		}
	}
}

func TestConanParseGraphContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := Conan{}.Parse(ctx, ParseInput{Path: "conan.lock", Content: []byte(conanLockV1GraphFixture)})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestConanRegistryGenerateIncludesGraphEdges(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "conan.lock"), []byte(conanLockV1GraphFixture), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}

	doc, err := reg.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if doc.Source != "ownsbom" || doc.GeneratorVersion != ownsbomVersion {
		t.Errorf("want source ownsbom and generator %s, got %s and %s", ownsbomVersion, doc.Source, doc.GeneratorVersion)
	}

	if len(doc.Components) != 5 {
		t.Errorf("want 5 components, got %d", len(doc.Components))
	}

	if len(doc.Dependencies) != 2 {
		t.Fatalf("want 2 dependencies, got %d: %+v", len(doc.Dependencies), doc.Dependencies)
	}
}

func TestConanParseV1GraphDeterministic(t *testing.T) {
	firstComps, firstDeps := parseConanTest(t, "conan.lock", []byte(conanLockV1GraphFixture))

	for i := 0; i < 20; i++ {
		comps, deps := parseConanTest(t, "conan.lock", []byte(conanLockV1GraphFixture))
		if !reflect.DeepEqual(firstComps, comps) {
			t.Fatalf("components not deterministic at iter %d", i)
		}
		if !reflect.DeepEqual(firstDeps, deps) {
			t.Fatalf("dependencies not deterministic at iter %d", i)
		}
	}
}

func TestConanParseV1PythonRequiresComponents(t *testing.T) {
	comps, deps := parseConanTest(t, "conan.lock", []byte(`{
		  "version": "0.4",
		  "graph_lock": {
		    "nodes": {
		      "0": {
		        "ref": "app/1.0",
		        "requires": ["1"],
		        "python_requires": ["build-config/2.0@company/stable"]
		      },
		      "1": { "ref": "lib/3.0" }
		    }
		  }
		}`))

	expectedComps := []sbom.Component{
		{Name: "app", Version: "1.0", PURL: "pkg:conan/app@1.0", Scope: sbom.ScopeProduction, Location: "conan.lock"},
		{Name: "build-config", Version: "2.0", PURL: "pkg:conan/build-config@2.0", Scope: sbom.ScopeDevelopment, Location: "conan.lock"},
		{Name: "lib", Version: "3.0", PURL: "pkg:conan/lib@3.0", Scope: sbom.ScopeProduction, Location: "conan.lock"},
	}

	if len(comps) != len(expectedComps) {
		t.Fatalf("want %d components, got %d", len(expectedComps), len(comps))
	}

	for i, c := range comps {
		e := expectedComps[i]
		if c.Name != e.Name || c.Version != e.Version || c.PURL != e.PURL || c.Scope != e.Scope || c.Location != e.Location {
			t.Errorf("comp %d: want %+v, got %+v", i, e, c)
		}
	}

	if len(deps) != 1 || deps[0].Ref != "pkg:conan/app@1.0" || len(deps[0].DependsOn) != 1 || deps[0].DependsOn[0] != "pkg:conan/lib@3.0" {
		t.Errorf("deps wrong, got: %+v", deps)
	}
}

func TestConanParseV1PythonRequiresNormalization(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		wantPURL string
	}{
		{"plain", "config/1.0", "pkg:conan/config@1.0"},
		{"user channel", "config/1.0@company/stable", "pkg:conan/config@1.0"},
		{"recipe revision", "config/1.0#rev123", "pkg:conan/config@1.0"},
		{"user channel and revision", "config/1.0@company/stable#rev123", "pkg:conan/config@1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := fmt.Sprintf(`{"version":"0.4","graph_lock":{"nodes":{"0":{"python_requires":["%s"]}}}}`, tt.ref)
			comps, _ := parseConanTest(t, "conan.lock", []byte(fixture))
			if len(comps) != 1 {
				t.Fatalf("want 1 component, got %d", len(comps))
			}
			if comps[0].PURL != tt.wantPURL {
				t.Errorf("want PURL %s, got %s", tt.wantPURL, comps[0].PURL)
			}
			if comps[0].Name != "config" || comps[0].Version != "1.0" {
				t.Errorf("name/version wrong: %s/%s", comps[0].Name, comps[0].Version)
			}
			if comps[0].Scope != sbom.ScopeDevelopment {
				t.Errorf("scope wrong, got %s", comps[0].Scope)
			}
		})
	}
}

func TestConanParseV1PythonRequiresDuplicate(t *testing.T) {
	comps, deps := parseConanTest(t, "conan.lock", []byte(`{
		  "version": "0.4",
		  "graph_lock": {
		    "nodes": {
		      "0": {
		        "ref": "app/1.0",
		        "python_requires": ["config/1.0", "config/1.0@company/stable", "config/1.0#rev123"]
		      },
		      "1": {
		        "ref": "lib/2.0",
		        "python_requires": ["config/1.0"]
		      }
		    }
		  }
		}`))
	if len(comps) != 3 {
		t.Fatalf("want 3 components (app, config, lib), got %d", len(comps))
	}
	if comps[1].PURL != "pkg:conan/config@1.0" {
		t.Errorf("config component missing or wrong order: %+v", comps[1])
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 dependencies from python_requires, got %d", len(deps))
	}
}

func TestConanParseV1PythonRequiresMalformed(t *testing.T) {
	comps, _ := parseConanTest(t, "conan.lock", []byte(`{
		  "version": "0.4",
		  "graph_lock": {
		    "nodes": {
		      "0": {
		        "python_requires": ["invalid-reference", "config/", " /1.0", "valid/2.0"]
		      }
		    }
		  }
		}`))
	if len(comps) != 1 {
		t.Fatalf("want 1 component, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:conan/valid@2.0" {
		t.Errorf("want valid/2.0, got %s", comps[0].PURL)
	}
}

func TestConanParseV1PythonRequiresRefLessRoot(t *testing.T) {
	comps, deps := parseConanTest(t, "conan.lock", []byte(`{
		  "version": "0.4",
		  "graph_lock": {
		    "nodes": {
		      "0": {
		        "path": "/project/conanfile.py",
		        "python_requires": ["build-config/2.0"]
		      },
		      "1": { "ref": "lib/3.0" }
		    }
		  }
		}`))

	if len(comps) != 2 || comps[0].PURL != "pkg:conan/build-config@2.0" || comps[1].PURL != "pkg:conan/lib@3.0" {
		t.Errorf("components wrong: %+v", comps)
	}
	if len(deps) != 0 {
		t.Errorf("deps should be empty")
	}
}

func TestConanParseV1PythonRequiresScopePrecedence(t *testing.T) {
	comps, _ := parseConanTest(t, "conan.lock", []byte(`{
		  "version": "0.4",
		  "graph_lock": {
		    "nodes": {
		      "1": {
		        "ref": "app/1.0",
		        "python_requires": ["config/1.0"]
		      },
		      "9": {
		        "ref": "config/1.0"
		      }
		    }
		  }
		}`))
	if len(comps) != 2 {
		t.Fatalf("want 2 comps")
	}
	var configComp sbom.Component
	for _, c := range comps {
		if c.Name == "config" {
			configComp = c
		}
	}
	if configComp.Scope != sbom.ScopeProduction {
		t.Errorf("want config to retain production scope, got %s", configComp.Scope)
	}
}

func TestConanParseV1PythonRequiresBackgroundPath(t *testing.T) {
	comps, _ := parseConanTest(t, "tests/integration/conan.lock", []byte(`{
		  "version": "0.4",
		  "graph_lock": {
		    "nodes": {
		      "0": { "ref": "app/1.0", "python_requires": ["config/1.0"] }
		    }
		  }
		}`))

	if len(comps) != 2 {
		t.Fatalf("want 2 components, got %d: %+v", len(comps), comps)
	}

	want := map[string]bool{
		"pkg:conan/app@1.0":    true,
		"pkg:conan/config@1.0": true,
	}

	for _, c := range comps {
		if !want[c.PURL] {
			t.Errorf("unexpected component: %+v", c)
		}
		if c.Scope != sbom.ScopeTest {
			t.Errorf("component %s: want scope %s, got %s", c.PURL, sbom.ScopeTest, c.Scope)
		}
	}
}

func TestConanParseV1PythonRequiresMixedEdgeKinds(t *testing.T) {
	comps, deps := parseConanTest(t, "conan.lock", []byte(`{
		  "version": "0.4",
		  "graph_lock": {
		    "nodes": {
		      "0": {
		        "ref": "app/1.0",
		        "requires": ["1"],
		        "build_requires": ["2"],
		        "python_requires": ["config/3.0"]
		      },
		      "1": { "ref": "runtime/1.0" },
		      "2": { "ref": "cmake/2.0" }
		    }
		  }
		}`))
	if len(comps) != 4 {
		t.Fatalf("want 4 components")
	}
	if len(deps) != 1 || len(deps[0].DependsOn) != 2 {
		t.Fatalf("want 1 dep with 2 edges, got %+v", deps)
	}
	if deps[0].DependsOn[0] != "pkg:conan/cmake@2.0" || deps[0].DependsOn[1] != "pkg:conan/runtime@1.0" {
		t.Errorf("DependsOn wrong: %v", deps[0].DependsOn)
	}
}

func TestConanParseV1PythonRequiresDoNotInferEdges(t *testing.T) {
	comps, deps := parseConanTest(t, "conan.lock", []byte(`{
		  "version": "0.4",
		  "graph_lock": {
		    "nodes": {
		      "0": {
		        "ref": "app/1.0",
		        "python_requires": ["direct-config/1.0", "transitive-base/2.0"]
		      }
		    }
		  }
		}`))
	if len(comps) != 3 {
		t.Fatalf("want 3 components")
	}
	if len(deps) != 0 {
		t.Errorf("dependencies should be nil, got: %+v", deps)
	}
}

func TestConanParseV1PythonRequiresDeterministic(t *testing.T) {
	fixture := []byte(`{
	  "version": "0.4",
	  "graph_lock": {
	    "nodes": {
	      "1": { "ref": "lib-b/1.0", "python_requires": ["config/1.0@user/chan#rev"] },
	      "0": { "ref": "app/1.0", "requires": ["1"], "python_requires": ["config/1.0"] }
	    }
	  }
	}`)
	firstComps, firstDeps := parseConanTest(t, "conan.lock", fixture)
	for i := 0; i < 20; i++ {
		comps, deps := parseConanTest(t, "conan.lock", fixture)
		if !reflect.DeepEqual(firstComps, comps) {
			t.Fatalf("components not deterministic at iter %d", i)
		}
		if !reflect.DeepEqual(firstDeps, deps) {
			t.Fatalf("dependencies not deterministic at iter %d", i)
		}
	}
}

func TestConanRegistryGenerateIncludesPythonRequires(t *testing.T) {
	dir := t.TempDir()
	fixture := []byte(`{"version": "0.4", "graph_lock": {"nodes": {"0": {"python_requires": ["config/1.0"]}}}}`)
	if err := os.WriteFile(filepath.Join(dir, "conan.lock"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}
	doc, err := reg.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if doc.Source != "ownsbom" || doc.GeneratorVersion != ownsbomVersion {
		t.Errorf("want source ownsbom and generator %s, got %s and %s", ownsbomVersion, doc.Source, doc.GeneratorVersion)
	}
	if len(doc.Components) != 1 || doc.Components[0].Name != "config" {
		t.Errorf("want 1 config component, got %+v", doc.Components)
	}
	if len(doc.Dependencies) != 0 {
		t.Errorf("want 0 dependencies, got %+v", doc.Dependencies)
	}
}
