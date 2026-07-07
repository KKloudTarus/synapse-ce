package bincat

import (
	"context"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestNormalizePyPI(t *testing.T) {
	cases := map[string]string{
		"Flask": "flask", "PyYAML": "pyyaml", "typing_extensions": "typing-extensions",
		"zope.interface": "zope-interface", "a__b--c..d": "a-b-c-d", "-x-": "x",
	}
	for in, want := range cases {
		if got := normalizePyPI(in); got != want {
			t.Errorf("normalizePyPI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidators(t *testing.T) {
	if !validGoModule("github.com/gin-gonic/gin") || !resolvedGoVersion("v1.9.1") {
		t.Error("a normal module path + resolved version must validate")
	}
	if resolvedGoVersion("(devel)") || resolvedGoVersion("") {
		t.Error("a source-build placeholder / empty version must be rejected")
	}
	if validGoModule("evil?x=1") || validGoModule("has space") || validIdent("a/b") || validIdent("v1?0") {
		t.Error("PURL-breaking characters must be rejected")
	}
}

func TestLooksLikeBinary(t *testing.T) {
	dir := t.TempDir()
	elf := filepath.Join(dir, "elf")
	if err := os.WriteFile(elf, []byte{0x7f, 'E', 'L', 'F', 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	txt := filepath.Join(dir, "txt")
	if err := os.WriteFile(txt, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !looksLikeBinary(elf) {
		t.Error("ELF magic must be recognized")
	}
	if looksLikeBinary(txt) {
		t.Error("a shell script must not look like a binary")
	}
}

func TestCatalogPythonDistInfo(t *testing.T) {
	rootfs := t.TempDir()
	meta := filepath.Join(rootfs, "usr/lib/python3.11/site-packages/Requests-2.31.0.dist-info/METADATA")
	if err := os.MkdirAll(filepath.Dir(meta), 0o755); err != nil {
		t.Fatal(err)
	}
	// The long description after the blank line must NOT be parsed for Name/Version.
	if err := os.WriteFile(meta, []byte("Metadata-Version: 2.1\nName: Requests\nVersion: 2.31.0\n\nName: NOT-THIS\nVersion: 9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	comps, err := New().CatalogInstalled(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(comps) != 1 || comps[0].PURL != "pkg:pypi/requests@2.31.0" || comps[0].Scope != "production" {
		t.Fatalf("want one normalized pkg:pypi/requests@2.31.0 (production), got %+v", comps)
	}
}

func TestBuildInfoComponents(t *testing.T) {
	// Hermetic: a go-test binary omits its dependency graph from build info, so exercise the mapping with a
	// synthetic BuildInfo instead (a normally-built binary DOES carry deps, so the e2e path works in production).
	bi := &debug.BuildInfo{
		Main: debug.Module{Path: "example.com/app", Version: "(devel)"}, // source build → filtered
		Deps: []*debug.Module{
			{Path: "github.com/gin-gonic/gin", Version: "v1.9.1"},
			{Path: "old.example/x", Version: "v0.0.0-0", Replace: &debug.Module{Path: "new.example/x", Version: "v2.0.0"}},
			{Path: "no.version/y", Version: ""}, // unresolved → filtered
		},
	}
	comps := buildInfoComponents(bi)
	purls := map[string]bool{}
	for _, c := range comps {
		purls[c.PURL] = true
		if c.Scope != "production" {
			t.Errorf("Go components should be production scope, got %q for %q", c.Scope, c.PURL)
		}
	}
	if !purls["pkg:golang/github.com/gin-gonic/gin@v1.9.1"] {
		t.Error("a resolved dependency must be cataloged")
	}
	if !purls["pkg:golang/new.example/x@v2.0.0"] { // replacement is used, not the original
		t.Error("a replaced dependency must be cataloged as its replacement")
	}
	if purls["pkg:golang/example.com/app@(devel)"] || len(comps) != 2 {
		t.Errorf("the (devel) main module and the empty-version dep must be filtered, got %d: %+v", len(comps), comps)
	}
}

func TestCatalogInstalledSmokeOnRealBinary(t *testing.T) {
	// The real buildinfo path must not crash on a genuine binary (a go-test binary carries no deps here, so we
	// only assert it runs cleanly + emits pkg:golang PURLs if any).
	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate test binary: %v", err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Skipf("cannot read test binary: %v", err)
	}
	rootfs := t.TempDir()
	dst := filepath.Join(rootfs, "usr", "bin", "app")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
	comps, err := New().CatalogInstalled(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog on a real binary must not error: %v", err)
	}
	for _, c := range comps {
		if c.PURL[:11] != "pkg:golang/" {
			t.Errorf("a binary-cataloged component must be pkg:golang, got %q", c.PURL)
		}
	}
}

func TestCatalogInstalledHonorsCancellation(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootfs, "f"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().CatalogInstalled(ctx, rootfs); err == nil {
		t.Error("a cancelled context must surface an error, not a silent partial catalog")
	}
}

func TestCatalogEmptyRootfs(t *testing.T) {
	comps, err := New().CatalogInstalled(context.Background(), t.TempDir())
	if err != nil || len(comps) != 0 {
		t.Errorf("empty rootfs: want no components + no error, got %d / %v", len(comps), err)
	}
	if c, _ := New().CatalogInstalled(context.Background(), ""); c != nil {
		t.Error("empty path: want nil")
	}
}
