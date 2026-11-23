package ownsbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheEligibilityFollowsManifestTraversal(t *testing.T) {
	registry, err := DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		path = filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package-lock.json", `{"lockfileVersion":3,"packages":{}}`)
	write("node_modules/ignored/pom.xml", `<project/>`)
	id, eligible, err := registry.SBOMProducerIdentity(context.Background(), dir)
	if err != nil || id == "" || !eligible {
		t.Fatalf("eligible npm tree: id=%q eligible=%v err=%v", id, eligible, err)
	}
	write("nested/POM.XML", `<project/>`)
	id2, eligible, err := registry.SBOMProducerIdentity(context.Background(), dir)
	if err != nil || eligible || id2 != id {
		t.Fatalf("nested Maven tree: id=%q eligible=%v err=%v", id2, eligible, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, eligible, err = registry.SBOMProducerIdentity(ctx, dir)
	if err == nil || eligible {
		t.Fatalf("cancelled traversal must not cache: eligible=%v err=%v", eligible, err)
	}
	_, eligible, err = registry.SBOMProducerIdentity(context.Background(), filepath.Join(dir, "missing"))
	if err == nil || eligible {
		t.Fatalf("missing target must not cache: eligible=%v err=%v", eligible, err)
	}
}

func TestCacheEligibilityRejectsOversizedManifest(t *testing.T) {
	registry, err := DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxManifestBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, eligible, err := registry.SBOMProducerIdentity(context.Background(), dir)
	if err == nil || eligible {
		t.Fatalf("oversized manifest must not cache: eligible=%v err=%v", eligible, err)
	}
}
