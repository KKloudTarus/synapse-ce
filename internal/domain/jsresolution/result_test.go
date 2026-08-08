package jsresolution

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

func TestNormalizeResultDeterministicAndComplete(t *testing.T) {
	t.Parallel()
	in := Result{
		Imports: []ImportResolution{
			{From: "src/z.ts", Specifier: "lodash/fp", Kind: modulegraph.ImportESMStatic, Status: StatusUnresolved, Package: PackageIdentity{Name: "lodash"}, Reason: "R2C deferred"},
			{From: "src/a.ts", Specifier: "fs", Kind: modulegraph.ImportCommonJS, Status: StatusBuiltin, Package: PackageIdentity{Name: "node:fs"}},
			{From: "src/a.ts", Specifier: "@scope/pkg/sub", Kind: modulegraph.ImportESMStatic, Status: StatusAmbiguous, Candidates: []PackageIdentity{{Name: "@scope/pkg", Version: "2"}, {Name: "@scope/pkg", Version: "1"}, {Name: "@scope/pkg", Version: "1"}}, Reason: "multiple versions"},
		},
		Coverage: []CoverageIssue{
			{Kind: CoverageUnsupportedAlias, Path: "src/z.ts", Detail: "  unsupported  "},
			{Kind: CoverageUnsupportedAlias, Path: "src/z.ts", Detail: "unsupported"},
		},
		GraphCoverage: []modulegraph.CoverageIssue{
			{Kind: modulegraph.CoverageDynamicImport, Path: "src/z.ts", Line: 7, Detail: " dynamic "},
		},
	}
	original := append([]ImportResolution(nil), in.Imports...)
	got, err := NormalizeResult(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete {
		t.Fatal("result with unresolved/ambiguous imports and coverage reported complete")
	}
	if len(got.Coverage) != 1 || got.Coverage[0].Detail != "unsupported" {
		t.Fatalf("coverage normalization = %#v", got.Coverage)
	}
	if got.GraphCoverage[0].Detail != "dynamic" {
		t.Fatalf("graph coverage normalization = %#v", got.GraphCoverage)
	}
	if got.Imports[0].Specifier != "@scope/pkg/sub" || got.Imports[1].Specifier != "fs" || got.Imports[2].Specifier != "lodash/fp" {
		t.Fatalf("import order = %#v", got.Imports)
	}
	if len(got.Imports[0].Candidates) != 2 || got.Imports[0].Candidates[0].Version != "1" {
		t.Fatalf("candidate normalization = %#v", got.Imports[0].Candidates)
	}
	if !reflect.DeepEqual(in.Imports, original) {
		t.Fatal("NormalizeResult mutated input imports")
	}
}

func TestNormalizeResultCanBeCompleteForResolvedPackageIdentities(t *testing.T) {
	t.Parallel()
	got, err := NormalizeResult(Result{Imports: []ImportResolution{
		{From: "src/a.ts", Specifier: "node:fs", Kind: modulegraph.ImportESMStatic, Status: StatusBuiltin, Package: PackageIdentity{Name: "node:fs"}},
		{From: "src/b.ts", Specifier: "@repo/shared", Kind: modulegraph.ImportESMStatic, Status: StatusWorkspace, Package: PackageIdentity{Name: "@repo/shared", Workspace: true, Path: "packages/shared"}},
		{From: "src/local.ts", Specifier: "@app/config", Kind: modulegraph.ImportESMStatic, Status: StatusLocal, Package: PackageIdentity{Name: "root", Path: "."}},
		{From: "src/c.ts", Specifier: "lodash", Kind: modulegraph.ImportESMStatic, Status: StatusComponent, Package: PackageIdentity{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("resolved result unexpectedly incomplete: %#v", got)
	}
}

func TestNormalizeResultRejectsStatusIdentityContractViolations(t *testing.T) {
	t.Parallel()
	cases := []ImportResolution{
		{From: "src/a.ts", Specifier: "fs", Kind: modulegraph.ImportESMStatic, Status: StatusBuiltin, Package: PackageIdentity{Name: "fs"}},
		{From: "src/a.ts", Specifier: "node:not-a-real-builtin", Kind: modulegraph.ImportESMStatic, Status: StatusBuiltin, Package: PackageIdentity{Name: "node:not-a-real-builtin"}},
		{From: "src/a.ts", Specifier: "x", Kind: modulegraph.ImportESMStatic, Status: StatusUnresolved, Package: PackageIdentity{Name: "node:fs"}, Reason: "wrong status for node identity"},
		{From: "src/a.ts", Specifier: "@repo/x", Kind: modulegraph.ImportESMStatic, Status: StatusWorkspace, Package: PackageIdentity{Name: "@repo/x", Path: "packages/x"}},
		{From: "src/a.ts", Specifier: "lodash", Kind: modulegraph.ImportESMStatic, Status: StatusUnresolved},
		{From: "src/a.ts", Specifier: "x", Kind: modulegraph.ImportESMStatic, Status: StatusAmbiguous, Candidates: []PackageIdentity{{Name: "a"}}, Reason: "one candidate is not ambiguity"},
		{From: "src/a.ts", Specifier: "https://x", Kind: modulegraph.ImportESMStatic, Status: StatusUnsupported, Package: PackageIdentity{Name: "x"}, Reason: "unsupported"},
	}
	for _, resolution := range cases {
		if _, err := NormalizeResult(Result{Imports: []ImportResolution{resolution}}); err == nil {
			t.Fatalf("invalid resolution shape accepted: %#v", resolution)
		}
	}
}
