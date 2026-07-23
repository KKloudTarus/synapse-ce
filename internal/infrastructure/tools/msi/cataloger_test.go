package msi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogArtifacts(t *testing.T) {
	dir := t.TempDir()
	data := buildTestMSI(t, []kv{
		{"ProductName", "GitHub CLI"},
		{"ProductVersion", "2.62.0"},
		{"Manufacturer", "GitHub, Inc."},
	})
	if err := os.WriteFile(filepath.Join(dir, "gh.msi"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-MSI file with a .msi extension must be skipped (best-effort, no crash).
	if err := os.WriteFile(filepath.Join(dir, "bogus.msi"), []byte("not a compound file"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-.msi file is ignored.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	comps, err := New().CatalogArtifacts(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 {
		t.Fatalf("want 1 component (bogus.msi skipped), got %d: %+v", len(comps), comps)
	}
	c := comps[0]
	if c.Name != "GitHub CLI" || c.Version != "2.62.0" {
		t.Errorf("component identity = %q@%q", c.Name, c.Version)
	}
	if c.Supplier != "GitHub, Inc." || c.SupplierSource == "" {
		t.Errorf("supplier = %q (%q)", c.Supplier, c.SupplierSource)
	}
	if c.PURL != "pkg:generic/github-inc/github-cli@2.62.0" {
		t.Errorf("purl = %q", c.PURL)
	}
	if c.Location != "gh.msi" {
		t.Errorf("location = %q, want gh.msi", c.Location)
	}
}

func TestCatalogArtifactsEmptyDir(t *testing.T) {
	comps, err := New().CatalogArtifacts(context.Background(), t.TempDir())
	if err != nil || comps != nil {
		t.Fatalf("empty dir: want nil,nil; got %+v,%v", comps, err)
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"GitHub, Inc.":  "github-inc",
		"Acme Corp":     "acme-corp",
		"7-Zip":         "7-zip",
		"  Spaces  ":    "spaces",
		"a/b\\c:d":      "a-b-c-d",
		"node.js":       "node.js",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}
