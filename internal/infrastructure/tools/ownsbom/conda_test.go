package ownsbom

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestCondaParse(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name: "conda and nested pip dependencies",
			content: `name: test

dependencies:
  - numpy
  - "python=3.11.9" # declared version
  - openssl=3.2.1=h5eee18b_1
  - pip:
      - Requests_Pkg==2.32.3
      - urllib3
  - zlib=1.3.1
variables:
  NOT_A_DEPENDENCY: ghost=9.9.9
`,
			want: []string{
				"pkg:conda/numpy",
				"pkg:conda/openssl@3.2.1?build=h5eee18b_1",
				"pkg:conda/python@3.11.9",
				"pkg:conda/zlib@1.3.1",
				"pkg:pypi/requests-pkg@2.32.3",
			},
		},
		{
			name: "compact pip indentation",
			content: `dependencies:
  - pip:
    - flask==2.3.3
  - click=8.1.7
`,
			want: []string{"pkg:conda/click@8.1.7", "pkg:pypi/flask@2.3.3"},
		},
		{
			name: "indentationless sequence",
			content: `dependencies:
- numpy
- python=3.11
- pip:
  - requests==2.32.3
`,
			want: []string{"pkg:conda/numpy", "pkg:conda/python@3.11", "pkg:pypi/requests@2.32.3"},
		},
		{
			name: "channel qualified dependency",
			content: `dependencies:
  - conda-forge::numpy=1.26.4=py312_0
`,
			want: []string{"pkg:conda/numpy@1.26.4?build=py312_0&channel=conda-forge"},
		},
		{
			name:    "no dependencies block",
			content: "name: empty\nchannels:\n  - conda-forge\n",
		},
		{
			name: "ranges remain unresolved and deduplicate",
			content: `dependencies:
  - numpy>=1.26
  - numpy=1.26.*
  - numpy
`,
			want: []string{"pkg:conda/numpy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comps, deps, err := Conda{}.Parse(context.Background(), ParseInput{Path: "environment.yml", Content: []byte(tt.content)})
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if deps != nil {
				t.Errorf("edges deferred; want nil deps, got %v", deps)
			}
			if len(comps) != len(tt.want) {
				t.Fatalf("components = %+v, want PURLs %v", comps, tt.want)
			}
			for i, wantPURL := range tt.want {
				if comps[i].PURL != wantPURL {
					t.Errorf("component[%d].PURL = %q, want %q", i, comps[i].PURL, wantPURL)
				}
				if comps[i].Location != "environment.yml" || comps[i].Scope != sbom.ScopeProduction {
					t.Errorf("component[%d] scope/location = %q/%q, want production/environment.yml", i, comps[i].Scope, comps[i].Location)
				}
			}
			if tt.name == "conda and nested pip dependencies" {
				if comps[0].Name != "numpy" || comps[0].Version != "" {
					t.Errorf("plain dependency = %+v, want unresolved numpy", comps[0])
				}
				if comps[1].Name != "openssl" || comps[1].Version != "3.2.1" {
					t.Errorf("build-qualified dependency = %+v, want openssl 3.2.1", comps[1])
				}
				if comps[4].Name != "requests-pkg" || comps[4].Version != "2.32.3" {
					t.Errorf("nested pip dependency = %+v, want requests-pkg 2.32.3", comps[4])
				}
			}
		})
	}
}

func TestCondaMetadata(t *testing.T) {
	if got := (Conda{}).Ecosystem(); got != "conda" {
		t.Fatalf("Ecosystem = %q, want conda", got)
	}
	markers := (Conda{}).Markers()
	if len(markers) != 2 || markers[0] != "environment.yml" || markers[1] != "environment.yaml" {
		t.Fatalf("Markers = %v, want [environment.yml environment.yaml]", markers)
	}
}

func TestCondaParseContextAndScannerErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := (Conda{}).Parse(ctx, ParseInput{Content: []byte("dependencies:\n  - numpy\n")}); err == nil {
		t.Fatal("Parse with canceled context returned nil error")
	}

	oversizedLine := "dependencies:\n  - package=" + strings.Repeat("1", (4<<20)+1)
	if _, _, err := (Conda{}).Parse(context.Background(), ParseInput{Content: []byte(oversizedLine)}); err == nil {
		t.Fatal("Parse with an overlong line returned nil error")
	}
}

func TestCondaRegistryGenerate(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "environment.yml"), `dependencies:
  - numpy
  - pandas=2.2.2=py312_0
  - pip:
    - flask==3.0.3
`)

	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}
	got, err := reg.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := []string{"pkg:conda/numpy", "pkg:conda/pandas@2.2.2?build=py312_0", "pkg:pypi/flask@3.0.3"}
	if len(got.Components) != len(want) {
		t.Fatalf("components = %+v, want PURLs %v", got.Components, want)
	}
	for i, wantPURL := range want {
		if got.Components[i].PURL != wantPURL {
			t.Errorf("component[%d].PURL = %q, want %q", i, got.Components[i].PURL, wantPURL)
		}
	}
}
