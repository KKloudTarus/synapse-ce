package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

type npmTestEdgeMeta struct {
	scope    string
	optional bool
}

func TestNPMEdgeScopeAndOptional(t *testing.T) {
	tests := []struct {
		name string
		lock string
		want map[string]npmTestEdgeMeta
	}{
		{
			name: "mixed runtime dev optional and shared runtime wins",
			lock: `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/parent":{"version":"1.0.0","dependencies":{"runtime":"1.0.0","shared":"1.0.0"},"devDependencies":{"dev-only":"1.0.0","shared":"1.0.0"},"optionalDependencies":{"optional":"1.0.0"}},"node_modules/runtime":{"version":"1.0.0"},"node_modules/dev-only":{"version":"1.0.0"},"node_modules/shared":{"version":"1.0.0"},"node_modules/optional":{"version":"1.0.0"}}}`,
			want: map[string]npmTestEdgeMeta{
				"pkg:npm/parent@1.0.0->pkg:npm/runtime@1.0.0":  {sbom.ScopeProduction, false},
				"pkg:npm/parent@1.0.0->pkg:npm/dev-only@1.0.0": {sbom.ScopeDevelopment, false},
				"pkg:npm/parent@1.0.0->pkg:npm/shared@1.0.0":   {sbom.ScopeProduction, false},
				"pkg:npm/parent@1.0.0->pkg:npm/optional@1.0.0": {sbom.ScopeProduction, true},
			},
		},
		{
			name: "dev package carries restriction to normal child edge",
			lock: `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/dev-parent":{"version":"1.0.0","dev":true,"dependencies":{"child":"1.0.0"}},"node_modules/child":{"version":"1.0.0","dev":true}}}`,
			want: map[string]npmTestEdgeMeta{
				"pkg:npm/dev-parent@1.0.0->pkg:npm/child@1.0.0": {sbom.ScopeDevelopment, false},
			},
		},
		{
			name: "cycle keeps deterministic production edge metadata",
			lock: `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/a":{"version":"1.0.0","dependencies":{"b":"1.0.0"}},"node_modules/b":{"version":"1.0.0","dependencies":{"a":"1.0.0"}}}}`,
			want: map[string]npmTestEdgeMeta{
				"pkg:npm/a@1.0.0->pkg:npm/b@1.0.0": {sbom.ScopeProduction, false},
				"pkg:npm/b@1.0.0->pkg:npm/a@1.0.0": {sbom.ScopeProduction, false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, deps, err := NPM{}.Parse(context.Background(), ParseInput{Path: "package-lock.json", Content: []byte(tt.lock)})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := map[string]npmTestEdgeMeta{}
			for _, d := range deps {
				for _, target := range d.DependsOn {
					got[d.Ref+"->"+target] = npmTestEdgeMeta{d.Scope, d.Optional}
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d edges, want %d: %#v", len(got), len(tt.want), got)
			}
			for edge, want := range tt.want {
				if got[edge] != want {
					t.Errorf("%s = %#v, want %#v", edge, got[edge], want)
				}
			}
		})
	}
}
