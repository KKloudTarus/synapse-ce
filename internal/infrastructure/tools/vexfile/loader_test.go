package vexfile

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const doc = `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/lodash@4.17.21"}],"status":"not_affected"}]}`

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".synapse.vex.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := New().Load(context.Background(), dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Statements) != 1 || got.Statements[0].Vulnerability != "CVE-2024-1" {
		t.Errorf("want 1 statement CVE-2024-1, got %+v", got)
	}
}

func TestLoadMissingIsEmptyNoError(t *testing.T) {
	got, err := New().Load(context.Background(), t.TempDir())
	if err != nil || len(got.Statements) != 0 {
		t.Errorf("a missing .synapse.vex.json must be an empty doc with no error, got doc=%+v err=%v", got, err)
	}
}

func TestLoadMalformedSurfacesError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".synapse.vex.json"), []byte(`{"not":"vex"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A present-but-invalid doc surfaces an error (so it's visible), and is fail-safe (nothing applied).
	if _, err := New().Load(context.Background(), dir); err == nil {
		t.Error("a malformed .synapse.vex.json must return an error to be surfaced, not silently ignored")
	}
}

func TestLoadSymlinkNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "evil.json")
	if err := os.WriteFile(outside, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".synapse.vex.json")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	got, err := New().Load(context.Background(), dir)
	if err != nil || len(got.Statements) != 0 {
		t.Errorf("a symlinked .synapse.vex.json must not be followed, got doc=%+v err=%v", got, err)
	}
}
