package jsresolution

import (
	"reflect"
	"testing"
)

func TestNormalizePackageName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "unscoped", input: " Lodash ", want: "lodash"},
		{name: "scoped", input: "@Scope/Pkg", want: "@scope/pkg"},
		{name: "subpath rejected", input: "lodash/fp", wantErr: true},
		{name: "empty scope", input: "@/pkg", wantErr: true},
		{name: "space", input: "bad name", wantErr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizePackageName(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("NormalizePackageName(%q) error = nil", test.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizePackageName(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("NormalizePackageName(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestNormalizeRepositoryLocationPreservesFilesystemNames(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "c:tmp", want: "c:tmp"},
		{input: `packages\private`, want: `packages\private`},
		{input: "packages/./a", want: "packages/a"},
	} {
		got, err := NormalizeRepositoryLocation(test.input)
		if err != nil {
			t.Fatalf("NormalizeRepositoryLocation(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("NormalizeRepositoryLocation(%q) = %q, want %q", test.input, got, test.want)
		}
	}
	for _, input := range []string{"/absolute", "../escape", "a/../../escape", "bad\x00name"} {
		if _, err := NormalizeRepositoryLocation(input); err == nil {
			t.Fatalf("NormalizeRepositoryLocation(%q) error = nil", input)
		}
	}
}

func TestNormalizeInventoryDeterministicAndNonMutating(t *testing.T) {
	t.Parallel()
	input := Inventory{
		Packages: []PackageMetadata{
			{Name: "@Scope/B", Path: "packages/b", Workspace: true, DeclaredBy: []MetadataDeclaration{{Source: "package.json", Pattern: `packages\*`}}},
			{Name: "a", Path: "packages/a", Workspace: true},
			{Name: "a", Path: "packages/a", Workspace: true},
		},
		Coverage: []CoverageIssue{
			{Kind: CoverageMalformedMetadata, Path: "packages/b/package.json", Detail: " malformed "},
			{Kind: CoverageMalformedMetadata, Path: "packages/b/package.json", Detail: "malformed"},
		},
		EntriesScanned: 10,
		FilesScanned:   3,
	}
	before := append([]PackageMetadata(nil), input.Packages...)
	got, err := NormalizeInventory(input)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete {
		t.Fatal("Complete = true with coverage issues")
	}
	if len(got.Packages) != 2 || len(got.Coverage) != 1 {
		t.Fatalf("counts packages=%d coverage=%d", len(got.Packages), len(got.Coverage))
	}
	if got.Packages[0].Path != "packages/a" || got.Packages[1].Name != "@scope/b" {
		t.Fatalf("unexpected deterministic ordering: %#v", got.Packages)
	}
	if got.Packages[1].DeclaredBy[0].Pattern != "packages/*" {
		t.Fatalf("declared pattern = %q", got.Packages[1].DeclaredBy[0].Pattern)
	}
	if !reflect.DeepEqual(input.Packages, before) {
		t.Fatalf("NormalizeInventory mutated input: %#v", input.Packages)
	}
}

func TestNormalizeInventoryCompleteWithoutCoverage(t *testing.T) {
	t.Parallel()
	got, err := NormalizeInventory(Inventory{Packages: []PackageMetadata{{Name: "pkg", Path: "."}}})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatal("Complete = false without coverage")
	}
}
