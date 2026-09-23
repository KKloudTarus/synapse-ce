package scabench

import (
	"bytes"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
)

func TestCommittedTrustedInputBindingSpecCoversEveryOriginPin(t *testing.T) {
	catalog, spec := committedTrustedInputBindingSpec(t)
	if err := spec.Validate(catalog); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got, want := len(spec.Bindings), len(ArchivablePins(catalog)); got != want {
		t.Fatalf("binding count = %d, want %d origin pins", got, want)
	}
}

func TestTrustedInputBindingSpecRejectsCoverageAndIdentityFailures(t *testing.T) {
	catalog, spec := committedTrustedInputBindingSpec(t)
	tests := []struct {
		name   string
		mutate func(*TrustedInputBindingSpec)
		want   string
	}{
		{
			name: "missing binding",
			mutate: func(value *TrustedInputBindingSpec) {
				value.Bindings = value.Bindings[1:]
			},
			want: "missing",
		},
		{
			name: "orphan reference",
			mutate: func(value *TrustedInputBindingSpec) {
				value.Bindings[0].Reference = "binary:absent"
			},
			want: "orphaned",
		},
		{
			name: "duplicate reference",
			mutate: func(value *TrustedInputBindingSpec) {
				value.Bindings[1].Reference = value.Bindings[0].Reference
			},
			want: "sorted",
		},
		{
			name: "duplicate locator",
			mutate: func(value *TrustedInputBindingSpec) {
				value.Bindings[1].Locator = value.Bindings[0].Locator
			},
			want: "duplicated",
		},
		{
			name: "unsafe locator",
			mutate: func(value *TrustedInputBindingSpec) {
				value.Bindings[0].Locator = "../tools/grype"
			},
			want: "safe root-relative",
		},
		{
			name: "pin digest mismatch",
			mutate: func(value *TrustedInputBindingSpec) {
				value.Bindings[0].PinDigest = "sha256:" + strings.Repeat("0", 64)
			},
			want: "does not match catalog pin digest",
		},
		{
			name: "catalog digest mismatch",
			mutate: func(value *TrustedInputBindingSpec) {
				value.CatalogDigest = "sha256:" + strings.Repeat("0", 64)
			},
			want: "does not match catalog digest",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneTrustedInputBindingSpec(spec)
			test.mutate(&candidate)
			if err := candidate.Validate(catalog); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTrustedInputArchiveBindsCanonicalManifestAndSpec(t *testing.T) {
	catalog, spec := committedTrustedInputBindingSpec(t)
	archive := validTrustedInputArchive(t, catalog, spec)
	if err := archive.ValidateForCatalog(catalog, spec); err != nil {
		t.Fatalf("ValidateForCatalog() error = %v", err)
	}
	archive.Inventory[0].Mode = 0o700
	if err := archive.Validate(); err == nil || !strings.Contains(err.Error(), "root manifest digest") {
		t.Fatalf("Validate() error = %v, want manifest identity failure", err)
	}
}

func TestTrustedInputArchiveRejectsMissingDirectoriesDuplicateAndTraversalEntries(t *testing.T) {
	catalog, spec := committedTrustedInputBindingSpec(t)
	archive := validTrustedInputArchive(t, catalog, spec)
	tests := []struct {
		name   string
		mutate func(*TrustedInputArchive)
		want   string
	}{
		{
			name: "missing parent directory",
			mutate: func(value *TrustedInputArchive) {
				for index, entry := range value.Inventory {
					if entry.Locator == "tools" {
						value.Inventory = append(value.Inventory[:index], value.Inventory[index+1:]...)
						return
					}
				}
			},
			want: "absent or not a directory",
		},
		{
			name: "duplicate inventory path",
			mutate: func(value *TrustedInputArchive) {
				value.Inventory = append(value.Inventory, value.Inventory[len(value.Inventory)-1])
				sort.Slice(value.Inventory, func(left, right int) bool { return value.Inventory[left].Locator < value.Inventory[right].Locator })
			},
			want: "sorted",
		},
		{
			name: "traversal inventory path",
			mutate: func(value *TrustedInputArchive) {
				value.Inventory[0].Locator = "../outside"
			},
			want: "safe root-relative",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := archive
			candidate.Bindings = append([]TrustedInputPinBinding(nil), archive.Bindings...)
			candidate.Inventory = append([]TrustedInputInventoryEntry(nil), archive.Inventory...)
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTrustedInputArchiveDecodeRejectsOversizedDocument(t *testing.T) {
	if _, err := DecodeTrustedInputArchive(bytes.NewReader(bytes.Repeat([]byte(" "), int(MaxTrustedInputArchiveManifestBytes)+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("DecodeTrustedInputArchive() error = %v, want size failure", err)
	}
}

func committedTrustedInputBindingSpec(t *testing.T) (Catalog, TrustedInputBindingSpec) {
	t.Helper()
	catalogFile, err := os.Open("corpus/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = catalogFile.Close() }()
	catalog, err := DecodeCatalog(catalogFile)
	if err != nil {
		t.Fatal(err)
	}
	specFile, err := os.Open("corpus/trusted-input-bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = specFile.Close() }()
	spec, err := DecodeTrustedInputBindingSpec(specFile)
	if err != nil {
		t.Fatal(err)
	}
	return catalog, spec
}

func cloneTrustedInputBindingSpec(spec TrustedInputBindingSpec) TrustedInputBindingSpec {
	copy := spec
	copy.Bindings = append([]TrustedInputPinBinding(nil), spec.Bindings...)
	return copy
}

func validTrustedInputArchive(t *testing.T, catalog Catalog, spec TrustedInputBindingSpec) TrustedInputArchive {
	t.Helper()
	entries := make(map[string]TrustedInputInventoryEntry)
	for _, binding := range spec.Bindings {
		for parent := path.Dir(binding.Locator); parent != "."; parent = path.Dir(parent) {
			entries[parent] = TrustedInputInventoryEntry{
				Locator: parent,
				Kind:    TrustedInputInventoryDirectory,
				Mode:    0o755,
			}
		}
		entry := TrustedInputInventoryEntry{Locator: binding.Locator, Mode: 0o644}
		if binding.Kind == TrustedInputPinTree {
			entry.Kind = TrustedInputInventoryDirectory
			entry.Mode = 0o755
		} else {
			entry.Kind = TrustedInputInventoryFile
			entry.ObjectDigest = binding.PinDigest
			entry.Bytes = 1
		}
		entries[entry.Locator] = entry
	}
	inventory := make([]TrustedInputInventoryEntry, 0, len(entries))
	for _, entry := range entries {
		inventory = append(inventory, entry)
	}
	sort.Slice(inventory, func(left, right int) bool { return inventory[left].Locator < inventory[right].Locator })
	archive, err := NewTrustedInputArchive(catalog, spec, inventory)
	if err != nil {
		t.Fatal(err)
	}
	return archive
}
