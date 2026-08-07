package jsresolution

import "testing"

func TestClassifySpecifier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		raw         string
		kind        SpecifierKind
		packageName string
		builtinName string
	}{
		{name: "node builtin", raw: "node:fs", kind: SpecifierBuiltin, builtinName: "node:fs"},
		{name: "bare builtin", raw: "fs/promises", kind: SpecifierBuiltin, builtinName: "node:fs/promises"},
		{name: "prefix only builtin", raw: "node:test", kind: SpecifierBuiltin, builtinName: "node:test"},
		{name: "prefix only builtin subpath", raw: "node:test/reporters", kind: SpecifierBuiltin, builtinName: "node:test/reporters"},
		{name: "newer prefix only builtin", raw: "node:sqlite", kind: SpecifierBuiltin, builtinName: "node:sqlite"},
		{name: "prefix only name remains package when bare", raw: "test", kind: SpecifierPackage, packageName: "test"},
		{name: "sqlite remains package when bare", raw: "sqlite", kind: SpecifierPackage, packageName: "sqlite"},
		{name: "unknown node scheme is unsupported", raw: "node:not-a-real-builtin", kind: SpecifierUnsupported},
		{name: "unscoped subpath", raw: "lodash/fp", kind: SpecifierPackage, packageName: "lodash"},
		{name: "scoped subpath", raw: "@scope/pkg/subpath", kind: SpecifierPackage, packageName: "@scope/pkg"},
		{name: "package import", raw: "#internal/logger", kind: SpecifierPackageImport},
		{name: "relative", raw: "../shared.js", kind: SpecifierRelative},
		{name: "url unsupported", raw: "https://example.test/mod.js", kind: SpecifierUnsupported},
		{name: "malformed scope", raw: "@scope", kind: SpecifierUnsupported},
		{name: "whitespace unsupported", raw: "lodash /fp", kind: SpecifierUnsupported},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifySpecifier(tt.raw)
			if got.Kind != tt.kind || got.PackageName != tt.packageName || got.BuiltinName != tt.builtinName || got.Raw != tt.raw {
				t.Fatalf("ClassifySpecifier(%q) = %#v", tt.raw, got)
			}
		})
	}
}
